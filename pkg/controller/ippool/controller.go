package ippool

import (
	"context"
	"fmt"
	"reflect"

	"github.com/rancher/wrangler/v3/pkg/kv"
	"github.com/rancher/wrangler/v3/pkg/relatedresource"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	"k8s.io/client-go/kubernetes"

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
)

const (
	controllerName = "vm-dhcp-ippool-controller"

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
	agentNamespace          string
	agentImage              *config.Image
	agentServiceAccountName string
	noAgent                 bool
	noDHCP                  bool

	cacheAllocator   *cache.CacheAllocator
	ipAllocator      *ipam.IPAllocator
	metricsAllocator *metrics.MetricsAllocator

	ippoolController ctlnetworkv1.IPPoolController
	ippoolClient     ctlnetworkv1.IPPoolClient
	ippoolCache      ctlnetworkv1.IPPoolCache

	k8sClient kubernetes.Interface
	podCache  ctlcorev1.PodCache

	nadClient ctlcniv1.NetworkAttachmentDefinitionClient
	nadCache  ctlcniv1.NetworkAttachmentDefinitionCache
}

func Register(ctx context.Context, management *config.Management) error {
	ippools := management.HarvesterNetworkFactory.Network().V1alpha1().IPPool()
	pods := management.CoreFactory.Core().V1().Pod()
	nads := management.CniFactory.K8s().V1().NetworkAttachmentDefinition()

	handler := &Handler{
		agentNamespace:          management.Options.AgentNamespace,
		agentImage:              management.Options.AgentImage,
		agentServiceAccountName: management.Options.AgentServiceAccountName,
		noAgent:                 management.Options.NoAgent,
		noDHCP:                  management.Options.NoDHCP,

		cacheAllocator:   management.CacheAllocator,
		ipAllocator:      management.IPAllocator,
		metricsAllocator: management.MetricsAllocator,

		ippoolController: ippools,
		ippoolClient:     ippools,
		ippoolCache:      ippools.Cache(),

		k8sClient: management.ClientSet,
		podCache:  pods.Cache(),

		nadClient: nads,
		nadCache:  nads.Cache(),
	}

	ctlnetworkv1.RegisterIPPoolStatusHandler(
		ctx,
		ippools,
		networkv1.Registered,
		"ippool-register",
		handler.DeployAgent,
	)
	ctlnetworkv1.RegisterIPPoolStatusHandler(
		ctx,
		ippools,
		networkv1.CacheReady,
		"ippool-cache-builder",
		handler.BuildCache,
	)
	ctlnetworkv1.RegisterIPPoolStatusHandler(
		ctx,
		ippools,
		networkv1.AgentReady,
		"ippool-agent-monitor",
		handler.MonitorAgent,
	)

	relatedresource.Watch(ctx, "ippool-trigger", func(namespace, name string, obj runtime.Object) ([]relatedresource.Key, error) {
		var keys []relatedresource.Key
		sets := labels.Set{
			"network.harvesterhci.io/vm-dhcp-controller": "agent",
		}
		pods, err := handler.podCache.List(namespace, sets.AsSelector())
		if err != nil {
			return nil, err
		}
		for _, pod := range pods {
			key := relatedresource.Key{
				Namespace: pod.Labels[util.IPPoolNamespaceLabelKey],
				Name:      pod.Labels[util.IPPoolNameLabelKey],
			}
			keys = append(keys, key)
		}
		return keys, nil
	}, ippools, pods)

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
		ipPoolCpy.Status.AgentPodRef = nil
		ipPoolCpy.Status.AgentDeploymentRef = nil
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

	return ipPool, nil
}

func (h *Handler) OnRemove(key string, ipPool *networkv1.IPPool) (*networkv1.IPPool, error) {
	if ipPool == nil {
		return nil, nil
	}

	logrus.Debugf("(ippool.OnRemove) ippool configuration %s/%s has been removed", ipPool.Namespace, ipPool.Name)

	if h.noAgent {
		return ipPool, nil
	}

	if err := h.cleanup(ipPool); err != nil {
		return ipPool, err
	}

	return ipPool, nil
}

// DeployAgent reconciles ipPool and ensures there's an agent deployment for it. The
// returned status reports whether an agent is registered.
func (h *Handler) DeployAgent(ipPool *networkv1.IPPool, status networkv1.IPPoolStatus) (networkv1.IPPoolStatus, error) {
	logrus.Debugf("(ippool.DeployAgent) deploy agent for ippool %s/%s", ipPool.Namespace, ipPool.Name)

	if ipPool.Spec.Paused != nil && *ipPool.Spec.Paused {
		return status, fmt.Errorf("ippool %s/%s was administratively disabled", ipPool.Namespace, ipPool.Name)
	}

	if h.noAgent {
		return status, nil
	}

	if h.k8sClient == nil {
		return status, fmt.Errorf("k8s client not initialized")
	}

	nadNamespace, nadName := kv.RSplit(ipPool.Spec.NetworkName, "/")
	nad, err := h.nadCache.Get(nadNamespace, nadName)
	if err != nil {
		return status, err
	}

	if nad.Labels == nil {
		return status, fmt.Errorf("could not find clusternetwork for nad %s", ipPool.Spec.NetworkName)
	}

	clusterNetwork, ok := nad.Labels[clusterNetworkLabelKey]
	if !ok {
		return status, fmt.Errorf("could not find clusternetwork for nad %s", ipPool.Spec.NetworkName)
	}

	desiredImage := h.getAgentImage(ipPool)

	// Best-effort cleanup of legacy agent pod (pre-deployment versions).
	if ipPool.Status.AgentPodRef != nil {
		legacy := ipPool.Status.AgentPodRef
		if err := h.k8sClient.CoreV1().Pods(legacy.Namespace).Delete(context.Background(), legacy.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return status, err
		}
		status.AgentPodRef = nil
	}

	agentDeployment, err := prepareAgentDeployment(ipPool, h.noDHCP, h.agentNamespace, clusterNetwork, h.agentServiceAccountName, desiredImage)
	if err != nil {
		return status, err
	}
	config.Scheme.Default(agentDeployment)

	deployments := h.k8sClient.AppsV1().Deployments(agentDeployment.Namespace)
	existing, err := deployments.Get(context.Background(), agentDeployment.Name, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return status, err
		}

		logrus.Infof("(ippool.DeployAgent) agent deployment for ippool %s/%s missing, creating", ipPool.Namespace, ipPool.Name)
		existing, err = deployments.Create(context.Background(), agentDeployment, metav1.CreateOptions{})
		if err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return status, err
			}
			existing, err = deployments.Get(context.Background(), agentDeployment.Name, metav1.GetOptions{})
			if err != nil {
				return status, err
			}
		}
	}

	if existing.DeletionTimestamp != nil {
		return status, fmt.Errorf("agent deployment %s marked for deletion", existing.Name)
	}

	if existing.Labels == nil ||
		existing.Labels[vmDHCPControllerLabelKey] != "agent" ||
		existing.Labels[util.IPPoolNamespaceLabelKey] != ipPool.Namespace ||
		existing.Labels[util.IPPoolNameLabelKey] != ipPool.Name {
		return status, fmt.Errorf("agent deployment %s label mismatch", existing.Name)
	}

	if existing.Spec.Selector == nil || !reflect.DeepEqual(existing.Spec.Selector, agentDeployment.Spec.Selector) {
		return status, fmt.Errorf("agent deployment %s selector mismatch", existing.Name)
	}

	updated := existing.DeepCopy()
	if updated.Labels == nil {
		updated.Labels = map[string]string{}
	}
	for k, v := range agentDeployment.Labels {
		updated.Labels[k] = v
	}
	updated.Spec.Selector = existing.Spec.Selector
	updated.Spec.Replicas = agentDeployment.Spec.Replicas
	updated.Spec.Strategy = agentDeployment.Spec.Strategy
	updated.Spec.Template = agentDeployment.Spec.Template
	config.Scheme.Default(updated)

	if !reflect.DeepEqual(existing.Spec, updated.Spec) || !reflect.DeepEqual(existing.Labels, updated.Labels) {
		existing, err = deployments.Update(context.Background(), updated, metav1.UpdateOptions{})
		if err != nil {
			return status, err
		}
	}

	if status.AgentDeploymentRef == nil {
		status.AgentDeploymentRef = new(networkv1.DeploymentReference)
	}

	status.AgentDeploymentRef.Namespace = existing.Namespace
	status.AgentDeploymentRef.Name = existing.Name
	status.AgentDeploymentRef.Image = desiredImage
	status.AgentDeploymentRef.UID = existing.UID

	return status, nil
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

// MonitorAgent reconciles ipPool and keeps an eye on the agent deployment. The
// returned status reports whether an agent is ready.
func (h *Handler) MonitorAgent(ipPool *networkv1.IPPool, status networkv1.IPPoolStatus) (networkv1.IPPoolStatus, error) {
	logrus.Debugf("(ippool.MonitorAgent) monitor agent for ippool %s/%s", ipPool.Namespace, ipPool.Name)

	if ipPool.Spec.Paused != nil && *ipPool.Spec.Paused {
		return status, fmt.Errorf("ippool %s/%s was administratively disabled", ipPool.Namespace, ipPool.Name)
	}

	if h.noAgent {
		return status, nil
	}

	if ipPool.Status.AgentDeploymentRef == nil {
		return status, fmt.Errorf("agent for ippool %s/%s is not deployed", ipPool.Namespace, ipPool.Name)
	}

	if h.k8sClient == nil {
		return status, fmt.Errorf("k8s client not initialized")
	}

	depRef := ipPool.Status.AgentDeploymentRef
	deployment, err := h.k8sClient.AppsV1().Deployments(depRef.Namespace).Get(context.Background(), depRef.Name, metav1.GetOptions{})
	if err != nil {
		return status, err
	}

	if deployment.DeletionTimestamp != nil {
		return status, fmt.Errorf("agent deployment %s marked for deletion", deployment.Name)
	}

	if len(deployment.Spec.Template.Spec.Containers) == 0 {
		return status, fmt.Errorf("agent deployment %s has no containers", deployment.Name)
	}

	if depRef.Image != "" && deployment.Spec.Template.Spec.Containers[0].Image != depRef.Image {
		return status, fmt.Errorf("agent deployment %s template image mismatch", deployment.Name)
	}

	podSets := labels.Set{
		vmDHCPControllerLabelKey:     "agent",
		util.IPPoolNamespaceLabelKey: ipPool.Namespace,
		util.IPPoolNameLabelKey:      ipPool.Name,
	}
	pods, err := h.podCache.List(depRef.Namespace, podSets.AsSelector())
	if err != nil {
		return status, err
	}

	var readyPods int
	for _, pod := range pods {
		if pod.DeletionTimestamp != nil {
			continue
		}
		if len(pod.Spec.Containers) == 0 {
			continue
		}
		if depRef.Image != "" && pod.Spec.Containers[0].Image != depRef.Image {
			continue
		}
		if isPodReady(pod) {
			readyPods++
		}
	}

	if readyPods == 0 {
		return status, fmt.Errorf("agent deployment %s not ready", deployment.Name)
	}
	if readyPods > 1 {
		return status, fmt.Errorf("agent deployment %s has multiple ready pods", deployment.Name)
	}

	return status, nil
}

func isPodReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func (h *Handler) getAgentImage(ipPool *networkv1.IPPool) string {
	if _, ok := ipPool.Annotations[holdIPPoolAgentUpgradeAnnotationKey]; ok {
		if ipPool.Status.AgentDeploymentRef != nil && ipPool.Status.AgentDeploymentRef.Image != "" {
			return ipPool.Status.AgentDeploymentRef.Image
		}
		if ipPool.Status.AgentPodRef != nil && ipPool.Status.AgentPodRef.Image != "" {
			return ipPool.Status.AgentPodRef.Image
		}
	}
	return h.agentImage.String()
}

func (h *Handler) cleanup(ipPool *networkv1.IPPool) error {
	if h.k8sClient != nil {
		if ipPool.Status.AgentDeploymentRef != nil {
			ref := ipPool.Status.AgentDeploymentRef
			logrus.Infof("(ippool.cleanup) remove the backing agent deployment %s/%s for ippool %s/%s", ref.Namespace, ref.Name, ipPool.Namespace, ipPool.Name)
			if err := h.k8sClient.AppsV1().Deployments(ref.Namespace).Delete(context.Background(), ref.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
		if ipPool.Status.AgentPodRef != nil {
			ref := ipPool.Status.AgentPodRef
			logrus.Infof("(ippool.cleanup) remove the legacy backing agent pod %s/%s for ippool %s/%s", ref.Namespace, ref.Name, ipPool.Namespace, ipPool.Name)
			if err := h.k8sClient.CoreV1().Pods(ref.Namespace).Delete(context.Background(), ref.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
	}

	if h.ipAllocator != nil {
		h.ipAllocator.DeleteIPSubnet(ipPool.Spec.NetworkName)
	}
	if h.cacheAllocator != nil {
		h.cacheAllocator.DeleteMACSet(ipPool.Spec.NetworkName)
	}
	if h.metricsAllocator != nil {
		h.metricsAllocator.DeleteIPPool(
			ipPool.Spec.NetworkName,
			ipPool.Spec.IPv4Config.CIDR,
			ipPool.Spec.NetworkName,
		)
	}

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
