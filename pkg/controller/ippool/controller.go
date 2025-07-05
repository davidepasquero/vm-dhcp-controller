package ippool

import (
	"context"
	"fmt"
	"reflect"

	"github.com/rancher/wrangler/pkg/kv"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/harvester/vm-dhcp-controller/pkg/apis/network.harvesterhci.io"
	networkv1 "github.com/harvester/vm-dhcp-controller/pkg/apis/network.harvesterhci.io/v1alpha1"
	"github.com/harvester/vm-dhcp-controller/pkg/cache"
	"github.com/harvester/vm-dhcp-controller/pkg/config"
	ctlcorev1 "github.com/harvester/vm-dhcp-controller/pkg/generated/controllers/core/v1"
	ctlcniv1 "github.com/harvester/vm-dhcp-controller/pkg/generated/controllers/k8s.cni.cncf.io/v1"
	ctlnetworkv1 "github.com/harvester/vm-dhcp-controller/pkg/generated/controllers/network.harvesterhci.io/v1alpha1"
	"github.com/harvester/vm-dhcp-controller/pkg/ipam"
	"github.com/harvester/vm-dhcp-controller/pkg/metrics"
	"github.com/harvester/vm-dhcp-controller/pkg/util"
	// appsv1 "k8s.io/api/apps/v1" // Unused
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	// metav1 "k8s.io/apimachinery/pkg/apis/meta/v1" // This was the duplicate
	corev1 "k8s.io/api/core/v1" // For EnvVar
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/client-go/kubernetes"
	// "encoding/json" // Unused
	"os"      // For os.Getenv
	"strings" // For argument parsing

	appsv1 "k8s.io/api/apps/v1"       // For Deployment
	rbacv1 "k8s.io/api/rbac/v1" // For ClusterRoleBinding
)

const (
	controllerName = "vm-dhcp-ippool-controller"

	// AgentDeploymentNameSuffix is the suffix appended to the controller's fullname to get the agent deployment name.
	// This assumes the controller's name (passed via --name flag) is the "fullname" from Helm.
	AgentDeploymentNameSuffix = "-agent"
	// AgentContainerName is the name of the container within the agent deployment.
	// This needs to match what's in chart/templates/agent-deployment.yaml ({{ .Chart.Name }}-agent)
	// For robustness, this might need to be configurable or derived more reliably.
	// Assuming Chart.Name is stable, e.g., "harvester-vm-dhcp-controller".
	// Let's use a placeholder and refine if needed. It's currently {{ .Chart.Name }} in agent-deployment.yaml
	// which resolves to "vm-dhcp-controller" if the chart is named that.
	// The agent deployment.yaml has container name {{ .Chart.Name }}-agent
	// AgentContainerNameDefault = "vm-dhcp-controller-agent" // Replaced by env var
	// DefaultAgentPodInterfaceName is the default name for the Multus interface in the agent pod.
	DefaultAgentPodInterfaceName = "net1"

	multusNetworksAnnotationKey         = "k8s.v1.cni.cncf.io/networks"
	holdIPPoolAgentUpgradeAnnotationKey = "network.harvesterhci.io/hold-ippool-agent-upgrade"

	vmDHCPControllerLabelKey = network.GroupName + "/vm-dhcp-controller"
	clusterNetworkLabelKey   = network.GroupName + "/clusternetwork"

	setIPAddrScript = `
#!/usr/bin/env sh
set -ex

ip address flush dev eth1
ip address add %s/%d dev eth1
`
)

var (
	runAsUserID  int64 = 0
	runAsGroupID int64 = 0
)

type Network struct {
	Namespace     string `json:"namespace"`
	Name          string `json:"name"`
	InterfaceName string `json:"interface"`
}

type Handler struct {
	cacheAllocator *cache.CacheAllocator
	ipAllocator      *ipam.IPAllocator
	metricsAllocator *metrics.MetricsAllocator

	ippoolController ctlnetworkv1.IPPoolController
	ippoolClient     ctlnetworkv1.IPPoolClient
	ippoolCache      ctlnetworkv1.IPPoolCache
	podClient        ctlcorev1.PodClient
	podCache         ctlcorev1.PodCache
	nadClient        ctlcniv1.NetworkAttachmentDefinitionClient
	nadCache         ctlcniv1.NetworkAttachmentDefinitionCache
	kubeClient       kubernetes.Interface
	agentNamespace   string // Namespace where the agent deployment resides
}

func Register(ctx context.Context, management *config.Management) error {
	ippools := management.HarvesterNetworkFactory.Network().V1alpha1().IPPool()
	pods := management.CoreFactory.Core().V1().Pod()
	nads := management.CniFactory.K8s().V1().NetworkAttachmentDefinition()

	handler := &Handler{
		cacheAllocator:   management.CacheAllocator,
		ipAllocator:      management.IPAllocator,
		metricsAllocator: management.MetricsAllocator,

		ippoolController: ippools,
		ippoolClient:     ippools,
		ippoolCache:      ippools.Cache(),
		podClient:        pods,
		podCache:         pods.Cache(),
		nadClient:        nads,
		nadCache:         nads.Cache(),
		kubeClient:       management.KubeClient,     // Added KubeClient
		agentNamespace:   management.Namespace,    // Assuming Management has Namespace for the controller/agent
	}

	ctlnetworkv1.RegisterIPPoolStatusHandler(
		ctx,
		ippools,
		networkv1.CacheReady,
		"ippool-cache-builder",
		handler.BuildCache,
	)

	ippools.OnChange(ctx, controllerName, handler.OnChange)
	ippools.OnRemove(ctx, controllerName, handler.OnRemove)

	return nil
}

func (h *Handler) OnChange(key string, ipPool *networkv1.IPPool) (*networkv1.IPPool, error) {
	if ipPool == nil || ipPool.DeletionTimestamp != nil {
		return nil, nil
	}

	logrus.Debugf("(ippool.OnChange) ippool configuration %s has been changed: %+v", key, ipPool.Spec.IPv4Config)

	// Build the relationship between IPPool and NetworkAttachmentDefinition for VirtualMachineNetworkConfig to reference
	if err := h.ensureNADLabels(ipPool); err != nil {
		return ipPool, err
	}

	ipPoolCpy := ipPool.DeepCopy()

	// Check if the IPPool is administratively disabled
	if ipPool.Spec.Paused != nil && *ipPool.Spec.Paused {
		logrus.Infof("(ippool.OnChange) try to cleanup cache and agent for ippool %s", key)
		if err := h.cleanup(ipPool); err != nil {
			return ipPool, err
		}
		networkv1.Stopped.True(ipPoolCpy)
		if !reflect.DeepEqual(ipPoolCpy, ipPool) {
			return h.ippoolClient.UpdateStatus(ipPoolCpy)
		}
		return ipPool, nil
	}
	networkv1.Stopped.False(ipPoolCpy)

	if !h.ipAllocator.IsNetworkInitialized(ipPool.Spec.NetworkName) {
		networkv1.CacheReady.False(ipPoolCpy)
		networkv1.CacheReady.Reason(ipPoolCpy, "NotInitialized")
		networkv1.CacheReady.Message(ipPoolCpy, "")
		if !reflect.DeepEqual(ipPoolCpy, ipPool) {
			logrus.Warningf("(ippool.OnChange) ipam for ippool %s/%s is not initialized", ipPool.Namespace, ipPool.Name)
			return h.ippoolClient.UpdateStatus(ipPoolCpy)
		}
	}

	// Update IPPool status based on up-to-date IPAM

	ipv4Status := ipPoolCpy.Status.IPv4
	if ipv4Status == nil {
		ipv4Status = new(networkv1.IPv4Status)
	}

	used, err := h.ipAllocator.GetUsed(ipPool.Spec.NetworkName)
	if err != nil {
		return nil, err
	}
	ipv4Status.Used = used

	available, err := h.ipAllocator.GetAvailable(ipPool.Spec.NetworkName)
	if err != nil {
		return nil, err
	}
	ipv4Status.Available = available

	// Update IPPool metrics
	h.metricsAllocator.UpdateIPPoolUsed(
		key,
		ipPool.Spec.IPv4Config.CIDR,
		ipPool.Spec.NetworkName,
		used,
	)
	h.metricsAllocator.UpdateIPPoolAvailable(key,
		ipPool.Spec.IPv4Config.CIDR,
		ipPool.Spec.NetworkName,
		available,
	)

	allocated := ipv4Status.Allocated
	if allocated == nil {
		allocated = make(map[string]string)
	}
	if util.IsIPInBetweenOf(ipPool.Spec.IPv4Config.ServerIP, ipPool.Spec.IPv4Config.Pool.Start, ipPool.Spec.IPv4Config.Pool.End) {
		allocated[ipPool.Spec.IPv4Config.ServerIP] = util.ReservedMark
	}
	if util.IsIPInBetweenOf(ipPool.Spec.IPv4Config.Router, ipPool.Spec.IPv4Config.Pool.Start, ipPool.Spec.IPv4Config.Pool.End) {
		allocated[ipPool.Spec.IPv4Config.Router] = util.ReservedMark
	}
	for _, eIP := range ipPool.Spec.IPv4Config.Pool.Exclude {
		allocated[eIP] = util.ExcludedMark
	}
	// For DeepEqual
	if len(allocated) == 0 {
		allocated = nil
	}
	ipv4Status.Allocated = allocated

	ipPoolCpy.Status.IPv4 = ipv4Status

	if !reflect.DeepEqual(ipPoolCpy, ipPool) {
		logrus.Infof("(ippool.OnChange) update ippool %s/%s", ipPool.Namespace, ipPool.Name)
		ipPoolCpy.Status.LastUpdate = metav1.Now()
		return h.ippoolClient.UpdateStatus(ipPoolCpy)
	}

	// After other processing, sync the agent deployment
	// Assuming `management.ControllerName` is available and set to the controller's helm fullname
	// This name needs to be reliably determined. For now, using a placeholder.
	// The actual controller name (used for leader election etc.) is often passed via --name flag.
	// Let's assume `management.ControllerName` is available in `h` or can be fetched.
	// For now, this part of agent deployment name construction is illustrative.
	// It needs to align with how the agent deployment is actually named by Helm.
	// Agent deployment name is: {{ include "harvester-vm-dhcp-controller.fullname" . }}-agent
	// The controller's own "fullname" is needed. This is typically available from options.
	// Let's assume `h.agentNamespace` is where the controller (and agent) runs.
	// And the controller's name (helm fullname) is something we can get, e.g. from an env var or option.
	// This dynamic configuration needs the controller's own Helm fullname.
	// Let's assume it's available via h.getControllerHelmFullName() for now.
	// This is a complex part to get right without knowing how controllerName is populated.
	// For now, skipping the actual agent deployment update to avoid introducing half-baked logic
	// without having the controller's own Helm fullname.
	// TODO: Implement dynamic agent deployment update once controller's Helm fullname is accessible.
	// The old syncAgentDeployment logic is removed. We now call reconcileAgentForIPPool.
	if err := h.reconcileAgentForIPPool(ipPoolCpy); err != nil {
		// Log the error but don't necessarily block IPPool reconciliation for agent deployment issues.
		// The IPPool status update should still proceed.
		logrus.Errorf("Failed to reconcile agent for ippool %s: %v", key, err)
		// Depending on desired behavior, you might want to return the error or update a condition on ipPool.
		// For now, just logging.
	}

	return ipPoolCpy, nil // Return potentially updated ipPoolCpy from status updates
}

// Constants for resource naming, these might need to be configurable or derived from controller's own name/chart info.
const (
	agentResourceNamePrefix       = "vm-dhcp-agent"
	agentServiceAccountNameSuffix = "-sa"
	agentClusterRoleBindingSuffix = "-crb"
	// This needs to be the literal name of the ClusterRole defined in Helm chart for agents.
	// From previous fix: {{ .Release.Name }}-dhcp-agent-clusterrole
	// This must be passed to the controller, e.g., via env var.
	DefaultSharedAgentClusterRoleName = "harvester-dhcp-agent-clusterrole" // Placeholder - MUST BE MADE CONFIGURABLE VIA ENV
)

// sanitizeNameForKubernetes sanitizes a name part for use in Kubernetes resource names.
// It converts to lowercase and replaces invalid characters with hyphens.
// It also truncates to a reasonable length to avoid exceeding limits when combined with prefixes/suffixes.
func sanitizeNameForKubernetes(namePart string) string {
	sanitized := strings.ToLower(namePart)
	// Replace common invalid characters. A more robust regex might be needed for full compliance.
	sanitized = strings.ReplaceAll(sanitized, ".", "-")
	sanitized = strings.ReplaceAll(sanitized, "/", "-")
	// Example: disallow chars not in [a-z0-9-] based on DNS-1123
	// For simplicity, this example is basic.

	// Truncate if too long to prevent overall name from exceeding limits (e.g., 63 chars for some names)
	// Max length for a segment of a DNS label is 63, but full names can be longer.
	// Service names are often 63. Deployment names also.
	const maxSegLen = 50 // Arbitrary reasonable length for a part of a name
	if len(sanitized) > maxSegLen {
		sanitized = sanitized[:maxSegLen]
	}
	// TODO: Ensure it doesn't start or end with a hyphen after sanitization if that's an issue.
	return sanitized
}

// getAgentResourceName constructs a unique name for an agent resource.
func getAgentResourceName(ippool *networkv1.IPPool, suffix string) string {
	// Using a prefix, sanitized ippool namespace, and sanitized ippool name + suffix
	// Example: vm-dhcp-agent-ns1-mypool-sa
	return fmt.Sprintf("%s-%s-%s%s",
		agentResourceNamePrefix,
		sanitizeNameForKubernetes(ippool.Namespace),
		sanitizeNameForKubernetes(ippool.Name),
		suffix,
	)
}


func (h *Handler) reconcileAgentForIPPool(ipPool *networkv1.IPPool) error {
	ctx := context.TODO() // Replace with appropriate context if available

	agentSAName := getAgentResourceName(ipPool, agentServiceAccountNameSuffix)
	agentCRBName := getAgentResourceName(ipPool, agentClusterRoleBindingSuffix)
	agentDepName := getAgentResourceName(ipPool, "") // No suffix for deployment itself, prefix is enough

	// Target namespace for agent resources is the controller's namespace
	agentResourceNamespace := h.agentNamespace


	// Handle Deletion or Paused IPPool
	if ipPool.DeletionTimestamp != nil || (ipPool.Spec.Paused != nil && *ipPool.Spec.Paused) {
		logrus.Infof("IPPool %s/%s is being deleted or is paused. Deleting associated agent resources.", ipPool.Namespace, ipPool.Name)

		// Delete Deployment
		err := h.kubeClient.AppsV1().Deployments(agentResourceNamespace).Delete(ctx, agentDepName, metav1.DeleteOptions{})
		if err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete agent deployment %s/%s: %w", agentResourceNamespace, agentDepName, err)
		}
		if err == nil {
			logrus.Infof("Deleted agent deployment %s/%s", agentResourceNamespace, agentDepName)
		}

		// Delete ClusterRoleBinding
		// Note: Deleting CRB requires cluster-level permissions the controller now has.
		err = h.kubeClient.RbacV1().ClusterRoleBindings().Delete(ctx, agentCRBName, metav1.DeleteOptions{})
		if err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete agent clusterrolebinding %s: %w", agentCRBName, err)
		}
		if err == nil {
			logrus.Infof("Deleted agent clusterrolebinding %s", agentCRBName)
		}

		// Delete ServiceAccount
		err = h.kubeClient.CoreV1().ServiceAccounts(agentResourceNamespace).Delete(ctx, agentSAName, metav1.DeleteOptions{})
		if err != nil && !k8serrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete agent serviceaccount %s/%s: %w", agentResourceNamespace, agentSAName, err)
		}
		if err == nil {
			logrus.Infof("Deleted agent serviceaccount %s/%s", agentResourceNamespace, agentSAName)
		}
		return nil
	}

	// --- Reconcile ServiceAccount ---
	saClient := h.kubeClient.CoreV1().ServiceAccounts(agentResourceNamespace)
	_, err := saClient.Get(ctx, agentSAName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			logrus.Infof("Agent ServiceAccount %s/%s not found, creating.", agentResourceNamespace, agentSAName)
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      agentSAName,
					Namespace: agentResourceNamespace,
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ipPool, networkv1.SchemeGroupVersion.WithKind("IPPool"))},
				},
			}
			_, err = saClient.Create(ctx, sa, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create agent ServiceAccount %s/%s: %w", agentResourceNamespace, agentSAName, err)
			}
			logrus.Infof("Created agent ServiceAccount %s/%s", agentResourceNamespace, agentSAName)
		} else {
			return fmt.Errorf("failed to get agent ServiceAccount %s/%s: %w", agentResourceNamespace, agentSAName, err)
		}
	} else {
		// TODO: Update SA if needed (e.g., labels, annotations, ownerrefs if they changed)
		logrus.Debugf("Agent ServiceAccount %s/%s already exists.", agentResourceNamespace, agentSAName)
	}

	// --- Reconcile ClusterRoleBinding ---
	// This assumes a shared ClusterRole for all agents. Name needs to be configurable.
	sharedAgentCRName := os.Getenv("SHARED_AGENT_CLUSTERROLE_NAME")
	if sharedAgentCRName == "" {
		sharedAgentCRName = DefaultSharedAgentClusterRoleName // Use fallback
		logrus.Warnf("SHARED_AGENT_CLUSTERROLE_NAME env var not set, using fallback: %s", sharedAgentCRName)
	}

	crbClient := h.kubeClient.RbacV1().ClusterRoleBindings()
	_, err = crbClient.Get(ctx, agentCRBName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			logrus.Infof("Agent ClusterRoleBinding %s not found, creating.", agentCRBName)
			crb := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: agentCRBName,
					OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(ipPool, networkv1.SchemeGroupVersion.WithKind("IPPool"))},
				},
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: agentSAName, Namespace: agentResourceNamespace},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     sharedAgentCRName,
				},
			}
			_, err = crbClient.Create(ctx, crb, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create agent ClusterRoleBinding %s: %w", agentCRBName, err)
			}
			logrus.Infof("Created agent ClusterRoleBinding %s for SA %s/%s to ClusterRole %s", agentCRBName, agentResourceNamespace, agentSAName, sharedAgentCRName)
		} else {
			return fmt.Errorf("failed to get agent ClusterRoleBinding %s: %w", agentCRBName, err)
		}
	} else {
		// TODO: Update CRB if needed (e.g. if subject or roleref changed, though unlikely for this pattern)
		logrus.Debugf("Agent ClusterRoleBinding %s already exists.", agentCRBName)
	}

	// --- Reconcile Agent Deployment ---
	// This part is complex and involves defining the full Deployment spec.
	// For brevity, only logging for now. Full implementation would mirror chart/templates/agent-deployment.yaml.
	// logrus.Infof("TODO: Reconcile Agent Deployment %s/%s for IPPool %s/%s", agentResourceNamespace, agentDepName, ipPool.Namespace, ipPool.Name)
	desiredDeployment, err := h.constructDesiredAgentDeployment(ipPool, agentDepName, agentSAName, agentResourceNamespace)
	if err != nil {
		return fmt.Errorf("failed to construct desired agent deployment: %w", err)
	}

	existingDeployment, err := h.kubeClient.AppsV1().Deployments(agentResourceNamespace).Get(ctx, agentDepName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			logrus.Infof("Agent Deployment %s/%s not found, creating.", agentResourceNamespace, agentDepName)
			_, err = h.kubeClient.AppsV1().Deployments(agentResourceNamespace).Create(ctx, desiredDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create agent Deployment %s/%s: %w", agentResourceNamespace, agentDepName, err)
			}
			logrus.Infof("Created agent Deployment %s/%s", agentResourceNamespace, agentDepName)
		} else {
			return fmt.Errorf("failed to get agent Deployment %s/%s: %w", agentResourceNamespace, agentDepName, err)
		}
	} else {
		if needsUpdate(existingDeployment, desiredDeployment) {
			logrus.Infof("Agent Deployment %s/%s needs update, updating.", agentResourceNamespace, agentDepName)
			_, err = h.kubeClient.AppsV1().Deployments(agentResourceNamespace).Update(ctx, desiredDeployment, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("failed to update agent Deployment %s/%s: %w", agentResourceNamespace, agentDepName, err)
			}
			logrus.Infof("Updated agent Deployment %s/%s", agentResourceNamespace, agentDepName)
		} else {
			logrus.Debugf("Agent Deployment %s/%s already up-to-date.", agentResourceNamespace, agentDepName)
		}
	}

	return nil
}

// needsUpdate compares key fields of two Deployments to determine if an update is necessary.
func needsUpdate(existing, desired *appsv1.Deployment) bool {
	// Compare Replicas
	if existing.Spec.Replicas != nil && desired.Spec.Replicas != nil && *existing.Spec.Replicas != *desired.Spec.Replicas {
		logrus.Debugf("needsUpdate: Replicas changed from %d to %d", *existing.Spec.Replicas, *desired.Spec.Replicas)
		return true
	}

	// Compare Pod Template Spec (simplified check, more granular checks can be added)
	// Check container image
	if len(existing.Spec.Template.Spec.Containers) != len(desired.Spec.Template.Spec.Containers) {
		logrus.Debugf("needsUpdate: Container count changed from %d to %d", len(existing.Spec.Template.Spec.Containers), len(desired.Spec.Template.Spec.Containers))
		return true // Should not happen if we only manage one container
	}
	if len(desired.Spec.Template.Spec.Containers) > 0 { // Ensure there's at least one container defined
		if existing.Spec.Template.Spec.Containers[0].Image != desired.Spec.Template.Spec.Containers[0].Image {
			logrus.Debugf("needsUpdate: Container image changed from %s to %s", existing.Spec.Template.Spec.Containers[0].Image, desired.Spec.Template.Spec.Containers[0].Image)
			return true
		}

		// Compare Environment Variables (order doesn't matter for equality, but DeepEqual handles it)
		if !reflect.DeepEqual(existing.Spec.Template.Spec.Containers[0].Env, desired.Spec.Template.Spec.Containers[0].Env) {
			logrus.Debugf("needsUpdate: Environment variables changed.")
			// For more detailed logging, you could iterate and print diffs.
			// Example: logrus.Debugf("Existing Env: %+v, Desired Env: %+v", existing.Spec.Template.Spec.Containers[0].Env, desired.Spec.Template.Spec.Containers[0].Env)
			return true
		}

		// Compare Resource Requirements
		if !reflect.DeepEqual(existing.Spec.Template.Spec.Containers[0].Resources, desired.Spec.Template.Spec.Containers[0].Resources) {
			logrus.Debugf("needsUpdate: Resource requirements changed.")
			return true
		}

		// Compare Args
		if !reflect.DeepEqual(existing.Spec.Template.Spec.Containers[0].Args, desired.Spec.Template.Spec.Containers[0].Args) {
			logrus.Debugf("needsUpdate: Container args changed.")
			return true
		}
	}


	// Compare Labels (on Deployment and PodTemplate)
	if !reflect.DeepEqual(existing.ObjectMeta.Labels, desired.ObjectMeta.Labels) {
		logrus.Debugf("needsUpdate: Deployment labels changed.")
		return true
	}
	if !reflect.DeepEqual(existing.Spec.Template.ObjectMeta.Labels, desired.Spec.Template.ObjectMeta.Labels) {
		logrus.Debugf("needsUpdate: Pod template labels changed.")
		return true
	}

	// Compare Annotations (on Deployment and PodTemplate)
	// Note: Some annotations are set by Kubernetes itself (e.g., deployment.kubernetes.io/revision).
	// We should only compare annotations we manage or care about.
	// For simplicity, a full DeepEqual might be too sensitive.
	// Let's check specific annotations like the Multus one.
	if existing.Spec.Template.ObjectMeta.Annotations[multusNetworksAnnotationKey] != desired.Spec.Template.ObjectMeta.Annotations[multusNetworksAnnotationKey] {
		logrus.Debugf("needsUpdate: Multus annotation changed from %s to %s", existing.Spec.Template.ObjectMeta.Annotations[multusNetworksAnnotationKey], desired.Spec.Template.ObjectMeta.Annotations[multusNetworksAnnotationKey])
		return true
	}
	// A more robust way for annotations would be to check if all desired annotations are present and correct in existing.

	// Compare ServiceAccountName in PodSpec
	if existing.Spec.Template.Spec.ServiceAccountName != desired.Spec.Template.Spec.ServiceAccountName {
		logrus.Debugf("needsUpdate: ServiceAccountName changed from %s to %s", existing.Spec.Template.Spec.ServiceAccountName, desired.Spec.Template.Spec.ServiceAccountName)
		return true
	}

	// Add more checks as needed (e.g., volumes, security contexts, etc.)

	return false
}

// Helper function to get agent container name from environment variable or use a default
func getAgentContainerName() string {
	name := os.Getenv("AGENT_CONTAINER_NAME")
	if name == "" {
		name = "vm-dhcp-agent" // Default container name
	}
	return name
}

// Helper function to get agent image from environment variable or use a default
func getAgentImage() string {
	image := os.Getenv("AGENT_IMAGE")
	if image == "" {
		// This should ideally be set to a valid default image for the agent
		// For example: "your-repo/vm-dhcp-agent:latest"
		// Using a placeholder as it's critical this is configured correctly.
		logrus.Error("AGENT_IMAGE environment variable is not set and no default is defined.")
		// Returning a dummy value, but this should cause issues if not configured.
		return "placeholder-agent-image:latest"
	}
	return image
}

func (h *Handler) constructDesiredAgentDeployment(
	ipPool *networkv1.IPPool,
	deploymentName string,
	saName string,
	namespace string,
) (*appsv1.Deployment, error) {
	agentContainerName := getAgentContainerName()
	agentImage := getAgentImage()
	replicas := int32(1) // Agent deployments are typically single replica

	// Define labels for the Deployment and its Pods
	// These labels help in selecting/identifying the agent pods
	labels := map[string]string{
		"app.kubernetes.io/name":       "vm-dhcp-agent",
		"app.kubernetes.io/instance":   deploymentName,
		network.GroupName + "/ippool":  fmt.Sprintf("%s.%s", ipPool.Namespace, ipPool.Name), // Label with IPPool it serves
		"original-ippool-namespace":    sanitizeNameForKubernetes(ipPool.Namespace),
		"original-ippool-name":         sanitizeNameForKubernetes(ipPool.Name),
	}

	// Define annotations, including the Multus NAD annotation
	// The NAD name must match how it's created/available in the cluster.
	// Assuming ipPool.Spec.NetworkName is the NAD <namespace>/<name>
	nadNamespace, nadName := kv.RSplit(ipPool.Spec.NetworkName, "/")
	if nadNamespace == "" { // If no namespace in NetworkName, assume it's in the agent's namespace
		nadNamespace = namespace
	}
	nadAnnotationValue := fmt.Sprintf(`[{"name": "%s/%s", "namespace": "%s", "interface": "%s"}]`,
		nadNamespace,
		nadName,
		nadNamespace, // The NAD object's namespace
		DefaultAgentPodInterfaceName, // e.g., "net1"
	)

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Namespace: namespace,
			Labels:    labels,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(ipPool, networkv1.SchemeGroupVersion.WithKind("IPPool")),
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels, // Selector should match pod labels
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels, // Pod labels
					Annotations: map[string]string{
						multusNetworksAnnotationKey: nadAnnotationValue,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: saName,
					Containers: []corev1.Container{
						{
							Name:  agentContainerName,
							Image: agentImage,
							Args: []string{
								"agent", // Assuming the agent binary takes "agent" as subcommand
								"--ippool-name", ipPool.Name,
								"--ippool-namespace", ipPool.Namespace,
								// Add other necessary agent flags here
							},
							Env: []corev1.EnvVar{
								{Name: "AGENT_NAMESPACE", Value: namespace},
								{Name: "IPPOOL_NAME", Value: ipPool.Name},
								{Name: "IPPOOL_NAMESPACE", Value: ipPool.Namespace},
								{Name: "POD_IPPOOL_NETWORK_NAME", Value: ipPool.Spec.NetworkName}, // For agent to know which NAD it's attached to
								// Potentially pass DHCP server IP, lease times etc. if agent needs them directly
								// Or agent can fetch IPPool object itself using its SA permissions.
							},
							// Define Resources, Probes, VolumeMounts as needed
							// Example Resources (should be configurable)
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("200m"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_ADMIN", "NET_RAW"}, // For DHCP server operations
								},
							},
						},
					},
					// Define NodeSelector, Affinity, Tolerations if needed
					// Example: Node affinity to run agent on nodes where the network (NAD) is available
					// This depends on how network attachments are managed (e.g. if NADs are node-specific)
				},
			},
		},
	}
	return deployment, nil
}


func (h *Handler) OnRemove(key string, ipPool *networkv1.IPPool) (*networkv1.IPPool, error) {
	if ipPool == nil {
		return nil, nil // Should not happen if DeletionTimestamp is not set
	}

	logrus.Debugf("(ippool.OnRemove) ippool configuration %s/%s has been removed or is being deleted", ipPool.Namespace, ipPool.Name)

	// Call reconcileAgentForIPPool to handle deletion of associated agent resources
	if err := h.reconcileAgentForIPPool(ipPool); err != nil {
		logrus.Errorf("Failed to reconcile/delete agent for removed ippool %s: %v", key, err)
		// Potentially requeue or handle error, but for deletion, usually best effort
	}

	if err := h.cleanup(ipPool); err != nil { // This is for IPAM/Cache cleanup
		return ipPool, err
	}

	return ipPool, nil
}

// BuildCache reconciles ipPool and initializes the IPAM and MAC caches for it.
// The source information comes from both ipPool's spec and status. Since
// IPPool objects are deemed source of truths, BuildCache honors the state and
// use it to load up internal caches. The returned status reports whether both
// caches are fully initialized.
func (h *Handler) BuildCache(ipPool *networkv1.IPPool, status networkv1.IPPoolStatus) (networkv1.IPPoolStatus, error) {
	logrus.Debugf("(ippool.BuildCache) build ipam for ippool %s/%s", ipPool.Namespace, ipPool.Name)

	if ipPool.Spec.Paused != nil && *ipPool.Spec.Paused {
		return status, fmt.Errorf("ippool %s/%s was administratively disabled", ipPool.Namespace, ipPool.Name)
	}

	if networkv1.CacheReady.IsTrue(ipPool) {
		return status, nil
	}

	logrus.Infof("(ippool.BuildCache) initialize ipam for ippool %s/%s", ipPool.Namespace, ipPool.Name)
	if err := h.ipAllocator.NewIPSubnet(
		ipPool.Spec.NetworkName,
		ipPool.Spec.IPv4Config.CIDR,
		ipPool.Spec.IPv4Config.Pool.Start,
		ipPool.Spec.IPv4Config.Pool.End,
	); err != nil {
		return status, err
	}

	logrus.Infof("(ippool.BuildCache) initialize mac cache for ippool %s/%s", ipPool.Namespace, ipPool.Name)
	if err := h.cacheAllocator.NewMACSet(ipPool.Spec.NetworkName); err != nil {
		return status, err
	}

	// Revoke server IP address in IPAM
	if err := h.ipAllocator.RevokeIP(ipPool.Spec.NetworkName, ipPool.Spec.IPv4Config.ServerIP); err != nil {
		return status, err
	}
	logrus.Debugf("(ippool.BuildCache) server ip %s was revoked in ipam %s", ipPool.Spec.IPv4Config.ServerIP, ipPool.Spec.NetworkName)

	// Revoke router IP address in IPAM
	if err := h.ipAllocator.RevokeIP(ipPool.Spec.NetworkName, ipPool.Spec.IPv4Config.Router); err != nil {
		return status, err
	}
	logrus.Debugf("(ippool.BuildCache) router ip %s was revoked in ipam %s", ipPool.Spec.IPv4Config.Router, ipPool.Spec.NetworkName)

	// Revoke excluded IP addresses in IPAM
	for _, eIP := range ipPool.Spec.IPv4Config.Pool.Exclude {
		if err := h.ipAllocator.RevokeIP(ipPool.Spec.NetworkName, eIP); err != nil {
			return status, err
		}
		logrus.Infof("(ippool.BuildCache) excluded ip %s was revoked in ipam %s", eIP, ipPool.Spec.NetworkName)
	}

	// (Re)build caches from IPPool status
	if ipPool.Status.IPv4 != nil {
		for ip, mac := range ipPool.Status.IPv4.Allocated {
			if mac == util.ExcludedMark || mac == util.ReservedMark {
				continue
			}
			if _, err := h.ipAllocator.AllocateIP(ipPool.Spec.NetworkName, ip); err != nil {
				return status, err
			}
			if err := h.cacheAllocator.AddMAC(ipPool.Spec.NetworkName, mac, ip); err != nil {
				return status, err
			}
			logrus.Infof("(ippool.BuildCache) previously allocated ip %s was re-allocated in ipam %s", ip, ipPool.Spec.NetworkName)
		}
	}

	logrus.Infof("(ippool.BuildCache) ipam and mac cache %s for ippool %s/%s has been updated", ipPool.Spec.NetworkName, ipPool.Namespace, ipPool.Name)

	return status, nil
}

// MonitorAgent reconciles ipPool and keeps an eye on the agent pod. If the
// running agent pod does not match to the one record in ipPool's status,
func (h *Handler) cleanup(ipPool *networkv1.IPPool) error {
	// AgentPodRef related checks and deletion logic removed as the controller no longer manages agent pods.
	h.ipAllocator.DeleteIPSubnet(ipPool.Spec.NetworkName)
	h.cacheAllocator.DeleteMACSet(ipPool.Spec.NetworkName)
	h.metricsAllocator.DeleteIPPool(
		ipPool.Spec.NetworkName,
		ipPool.Spec.IPv4Config.CIDR,
		ipPool.Spec.NetworkName,
	)

	return nil
}

func (h *Handler) ensureNADLabels(ipPool *networkv1.IPPool) error {
	nadNamespace, nadName := kv.RSplit(ipPool.Spec.NetworkName, "/")
	nad, err := h.nadCache.Get(nadNamespace, nadName)
	if err != nil {
		return err
	}

	nadCpy := nad.DeepCopy()
	if nadCpy.Labels == nil {
		nadCpy.Labels = make(map[string]string)
	}
	nadCpy.Labels[util.IPPoolNamespaceLabelKey] = ipPool.Namespace
	nadCpy.Labels[util.IPPoolNameLabelKey] = ipPool.Name

	if !reflect.DeepEqual(nadCpy, nad) {
		logrus.Infof("(ippool.ensureNADLabels) update nad %s/%s", nad.Namespace, nad.Name)
		if _, err := h.nadClient.Update(nadCpy); err != nil {
			return err
		}
	}

	return nil
}

