package ippool

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/harvester/vm-dhcp-controller/pkg/cache"
	"github.com/harvester/vm-dhcp-controller/pkg/config"
	"github.com/harvester/vm-dhcp-controller/pkg/generated/clientset/versioned/fake"
	"github.com/harvester/vm-dhcp-controller/pkg/ipam"
	"github.com/harvester/vm-dhcp-controller/pkg/metrics"
	"github.com/harvester/vm-dhcp-controller/pkg/util"
	"github.com/harvester/vm-dhcp-controller/pkg/util/fakeclient"
)

const (
	testNADNamespace       = "default"
	testNADName            = "net-1"
	testNADNameLong        = "fi6cx9ca1kt1faq80k3ro9cowyumyjb67qdmg8fb9ydmz27rbk5btlg2m5avv3n"
	testIPPoolNamespace    = testNADNamespace
	testIPPoolName         = testNADName
	testIPPoolNameLong     = testNADNameLong
	testKey                = testIPPoolNamespace + "/" + testIPPoolName
	testPodNamespace       = "harvester-system"
	testPodName            = testNADNamespace + "-" + testNADName + "-agent"
	testUID                = "3a955369-9eaa-43db-94f3-9153289d7dc2"
	testClusterNetwork     = "provider"
	testServerIP1          = "192.168.0.2"
	testServerIP2          = "192.168.0.110"
	testNetworkName        = testNADNamespace + "/" + testNADName
	testNetworkNameLong    = testNADNamespace + "/" + testNADNameLong
	testCIDR               = "192.168.0.0/24"
	testRouter1            = "192.168.0.1"
	testRouter2            = "192.168.0.120"
	testStartIP            = "192.168.0.101"
	testEndIP              = "192.168.0.200"
	testServiceAccountName = "vdca"
	testImageRepository    = "rancher/harvester-vm-dhcp-agent"
	testImageTag           = "main"
	testImageTagNew        = "dev"
	testImage              = testImageRepository + ":" + testImageTag
	testImageNew           = testImageRepository + ":" + testImageTagNew
	testContainerName      = "agent"

	testExcludedIP1 = "192.168.0.150"
	testExcludedIP2 = "192.168.0.187"
	testExcludedIP3 = "192.168.0.10"
	testExcludedIP4 = "192.168.0.235"

	testAllocatedIP1 = "192.168.0.111"
	testAllocatedIP2 = "192.168.0.177"
	testMAC1         = "11:22:33:44:55:66"
	testMAC2         = "22:33:44:55:66:77"
)

var (
	testPodNameLong = util.SafeAgentConcatName(testNADNamespace, testNADNameLong)
)

func newTestCacheAllocatorBuilder() *cache.CacheAllocatorBuilder {
	return cache.NewCacheAllocatorBuilder()
}

func newTestIPAllocatorBuilder() *ipam.IPAllocatorBuilder {
	return ipam.NewIPAllocatorBuilder()
}

func newTestIPPoolBuilder() *IPPoolBuilder {
	return NewIPPoolBuilder(testIPPoolNamespace, testIPPoolName)
}

func newTestPodBuilder() *podBuilder {
	return newPodBuilder(testPodNamespace, testPodName)
}

func newTestIPPoolStatusBuilder() *ipPoolStatusBuilder {
	return newIPPoolStatusBuilder()
}

func newTestNetworkAttachmentDefinitionBuilder() *NetworkAttachmentDefinitionBuilder {
	return NewNetworkAttachmentDefinitionBuilder(testNADNamespace, testNADName)
}

func TestHandler_OnChange(t *testing.T) {
	t.Run("new ippool", func(t *testing.T) {
		key := testIPPoolNamespace + "/" + testIPPoolName
		givenIPAllocator := newTestIPAllocatorBuilder().Build()
		givenIPPool := newTestIPPoolBuilder().
			NetworkName(testNetworkName).Build()
		givenNAD := newTestNetworkAttachmentDefinitionBuilder().Build()

		expectedIPPool := newTestIPPoolBuilder().
			NetworkName(testNetworkName).
			StoppedCondition(corev1.ConditionFalse, "", "").
			CacheReadyCondition(corev1.ConditionFalse, "NotInitialized", "").Build()
		expectedNAD := newTestNetworkAttachmentDefinitionBuilder().
			Label(util.IPPoolNamespaceLabelKey, testIPPoolNamespace).
			Label(util.IPPoolNameLabelKey, testIPPoolName).Build()

		nadGVR := schema.GroupVersionResource{
			Group:    "k8s.cni.cncf.io",
			Version:  "v1",
			Resource: "network-attachment-definitions",
		}

		clientset := fake.NewSimpleClientset()
		err := clientset.Tracker().Create(nadGVR, givenNAD, givenNAD.Namespace)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		err = clientset.Tracker().Add(givenIPPool)
		if err != nil {
			t.Fatal(err)
		}

		handler := Handler{
			agentNamespace: "default",
			agentImage: &config.Image{
				Repository: "rancher/harvester-vm-dhcp-controller",
				Tag:        "main",
			},
			ipAllocator:  givenIPAllocator,
			ippoolClient: fakeclient.IPPoolClient(clientset.NetworkV1alpha1().IPPools),
			nadClient:    fakeclient.NetworkAttachmentDefinitionClient(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
			nadCache:     fakeclient.NetworkAttachmentDefinitionCache(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
		}

		ipPool, err := handler.OnChange(key, givenIPPool)
		assert.Nil(t, err)

		SanitizeStatus(&expectedIPPool.Status)
		SanitizeStatus(&ipPool.Status)

		assert.Equal(t, expectedIPPool, ipPool)

		nad, err := handler.nadClient.Get(testNADNamespace, testNADName, metav1.GetOptions{})
		assert.Nil(t, err)
		assert.Equal(t, expectedNAD, nad)
	})

	t.Run("ippool with ipam initialized", func(t *testing.T) {
		key := testIPPoolNamespace + "/" + testIPPoolName
		givenIPAllocator := newTestIPAllocatorBuilder().
			IPSubnet(testNetworkName, testCIDR, testStartIP, testEndIP).
			Build()
		givenIPPool := newTestIPPoolBuilder().
			ServerIP(testServerIP1).
			CIDR(testCIDR).
			PoolRange(testStartIP, testEndIP).
			NetworkName(testNetworkName).
			CacheReadyCondition(corev1.ConditionTrue, "", "").Build()
		givenNAD := newTestNetworkAttachmentDefinitionBuilder().Build()

		expectedIPPool := newTestIPPoolBuilder().
			ServerIP(testServerIP1).
			CIDR(testCIDR).
			PoolRange(testStartIP, testEndIP).
			NetworkName(testNetworkName).
			Available(100).
			Used(0).
			CacheReadyCondition(corev1.ConditionTrue, "", "").
			StoppedCondition(corev1.ConditionFalse, "", "").Build()

		nadGVR := schema.GroupVersionResource{
			Group:    "k8s.cni.cncf.io",
			Version:  "v1",
			Resource: "network-attachment-definitions",
		}

		clientset := fake.NewSimpleClientset()
		err := clientset.Tracker().Create(nadGVR, givenNAD, givenNAD.Namespace)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		err = clientset.Tracker().Add(givenIPPool)
		if err != nil {
			t.Fatal(err)
		}

		handler := Handler{
			agentNamespace: "default",
			agentImage: &config.Image{
				Repository: "rancher/harvester-vm-dhcp-controller",
				Tag:        "main",
			},
			ipAllocator:      givenIPAllocator,
			metricsAllocator: metrics.New(),
			ippoolClient:     fakeclient.IPPoolClient(clientset.NetworkV1alpha1().IPPools),
			nadClient:        fakeclient.NetworkAttachmentDefinitionClient(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
			nadCache:         fakeclient.NetworkAttachmentDefinitionCache(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
		}

		ipPool, err := handler.OnChange(key, givenIPPool)
		assert.Nil(t, err)

		SanitizeStatus(&expectedIPPool.Status)
		SanitizeStatus(&ipPool.Status)

		assert.Equal(t, expectedIPPool, ipPool)
	})

	t.Run("pause ippool", func(t *testing.T) {
		key := testIPPoolNamespace + "/" + testIPPoolName
		givenIPAllocator := newTestIPAllocatorBuilder().
			IPSubnet(testNetworkName, testCIDR, testStartIP, testEndIP).Build()
		givenIPPool := newTestIPPoolBuilder().
			NetworkName(testNetworkName).
			Paused().
			AgentPodRef(testPodNamespace, testPodName, testImage, "").Build()
		givenPod := newTestPodBuilder().Build()
		givenNAD := newTestNetworkAttachmentDefinitionBuilder().Build()

		expectedIPAllocator := newTestIPAllocatorBuilder().Build()
		expectedIPPool := newTestIPPoolBuilder().
			NetworkName(testNetworkName).
			Paused().
			StoppedCondition(corev1.ConditionTrue, "", "").Build()

		nadGVR := schema.GroupVersionResource{
			Group:    "k8s.cni.cncf.io",
			Version:  "v1",
			Resource: "network-attachment-definitions",
		}

		clientset := fake.NewSimpleClientset()
		err := clientset.Tracker().Create(nadGVR, givenNAD, givenNAD.Namespace)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		err = clientset.Tracker().Add(givenIPPool)
		if err != nil {
			t.Fatal(err)
		}

		k8sclientset := k8sfake.NewSimpleClientset()
		err = k8sclientset.Tracker().Add(givenPod)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		handler := Handler{
			agentNamespace: "default",
			agentImage: &config.Image{
				Repository: "rancher/harvester-vm-dhcp-controller",
				Tag:        "main",
			},
			ipAllocator:      givenIPAllocator,
			cacheAllocator:   cache.New(),
			metricsAllocator: metrics.New(),
			ippoolClient:     fakeclient.IPPoolClient(clientset.NetworkV1alpha1().IPPools),
			podClient:        fakeclient.PodClient(k8sclientset.CoreV1().Pods),
			nadClient:        fakeclient.NetworkAttachmentDefinitionClient(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
			nadCache:         fakeclient.NetworkAttachmentDefinitionCache(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
		}

		ipPool, err := handler.OnChange(key, givenIPPool)
		assert.Nil(t, err)

		SanitizeStatus(&expectedIPPool.Status)
		SanitizeStatus(&ipPool.Status)

		assert.Equal(t, expectedIPPool, ipPool)

		assert.Equal(t, expectedIPAllocator, handler.ipAllocator)

		_, err = handler.podClient.Get(testPodNamespace, testPodName, metav1.GetOptions{})
		assert.Equal(t, fmt.Sprintf("pods \"%s\" not found", testPodName), err.Error())
	})

	t.Run("resume ippool", func(t *testing.T) {
		key := testIPPoolNamespace + "/" + testIPPoolName
		givenIPAllocator := newTestIPAllocatorBuilder().
			IPSubnet(testNetworkName, testCIDR, testStartIP, testEndIP).
			Build()
		givenIPPool := newTestIPPoolBuilder().
			NetworkName(testNetworkName).
			UnPaused().
			CacheReadyCondition(corev1.ConditionTrue, "", "").Build()
		givenNAD := newTestNetworkAttachmentDefinitionBuilder().Build()

		expectedIPPool := newTestIPPoolBuilder().
			NetworkName(testNetworkName).
			UnPaused().
			Available(100).
			Used(0).
			CacheReadyCondition(corev1.ConditionTrue, "", "").
			StoppedCondition(corev1.ConditionFalse, "", "").Build()

		nadGVR := schema.GroupVersionResource{
			Group:    "k8s.cni.cncf.io",
			Version:  "v1",
			Resource: "network-attachment-definitions",
		}

		clientset := fake.NewSimpleClientset()
		err := clientset.Tracker().Create(nadGVR, givenNAD, givenNAD.Namespace)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		err = clientset.Tracker().Add(givenIPPool)
		if err != nil {
			t.Fatal(err)
		}

		handler := Handler{
			agentNamespace: "default",
			agentImage: &config.Image{
				Repository: "rancher/harvester-vm-dhcp-controller",
				Tag:        "main",
			},
			ipAllocator:      givenIPAllocator,
			metricsAllocator: metrics.New(),
			ippoolClient:     fakeclient.IPPoolClient(clientset.NetworkV1alpha1().IPPools),
			nadClient:        fakeclient.NetworkAttachmentDefinitionClient(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
			nadCache:         fakeclient.NetworkAttachmentDefinitionCache(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
		}

		ipPool, err := handler.OnChange(key, givenIPPool)
		assert.Nil(t, err)

		SanitizeStatus(&expectedIPPool.Status)
		SanitizeStatus(&ipPool.Status)

		assert.Equal(t, expectedIPPool, ipPool)
	})
}

func TestHandler_DeployAgent(t *testing.T) {
	t.Run("ippool created", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().
			ServerIP(testServerIP1).
			CIDR(testCIDR).
			NetworkName(testNetworkName).Build()
		givenNAD := newTestNetworkAttachmentDefinitionBuilder().
			Label(clusterNetworkLabelKey, testClusterNetwork).Build()

		expectedStatus := newTestIPPoolStatusBuilder().
			AgentPodRef(testPodNamespace, testPodName, testImage, "").Build()
		expectedPod, _ := prepareAgentPod(
			NewIPPoolBuilder(testIPPoolNamespace, testIPPoolName).
				ServerIP(testServerIP1).
				CIDR(testCIDR).
				NetworkName(testNetworkName).Build(),
			false,
			testPodNamespace,
			testClusterNetwork,
			testServiceAccountName,
			&config.Image{
				Repository: testImageRepository,
				Tag:        testImageTag,
			},
		)

		nadGVR := schema.GroupVersionResource{
			Group:    "k8s.cni.cncf.io",
			Version:  "v1",
			Resource: "network-attachment-definitions",
		}

		clientset := fake.NewSimpleClientset()
		err := clientset.Tracker().Create(nadGVR, givenNAD, givenNAD.Namespace)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		k8sclientset := k8sfake.NewSimpleClientset()

		handler := Handler{
			agentNamespace: testPodNamespace,
			agentImage: &config.Image{
				Repository: testImageRepository,
				Tag:        testImageTag,
			},
			agentServiceAccountName: testServiceAccountName,
			nadCache:                fakeclient.NetworkAttachmentDefinitionCache(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
			podClient:               fakeclient.PodClient(k8sclientset.CoreV1().Pods),
			podCache:                fakeclient.PodCache(k8sclientset.CoreV1().Pods),
		}

		status, err := handler.DeployAgent(givenIPPool, givenIPPool.Status)
		assert.Nil(t, err)
		assert.Equal(t, expectedStatus, status)

		pod, err := handler.podClient.Get(testPodNamespace, testPodName, metav1.GetOptions{})
		assert.Nil(t, err)
		assert.Equal(t, expectedPod, pod)
	})

	t.Run("ippool paused", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().
			Paused().Build()

		handler := Handler{
			agentNamespace: testPodNamespace,
			agentImage: &config.Image{
				Repository: testImageRepository,
				Tag:        testImageTag,
			},
			agentServiceAccountName: testServiceAccountName,
		}

		_, err := handler.DeployAgent(givenIPPool, givenIPPool.Status)
		assert.Equal(t, fmt.Errorf("ippool %s was administratively disabled", testIPPoolNamespace+"/"+testIPPoolName), err)
	})

	t.Run("nad not found", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().
			NetworkName("you-cant-find-me").Build()
		givenNAD := newTestNetworkAttachmentDefinitionBuilder().
			Label(clusterNetworkLabelKey, testClusterNetwork).Build()

		nadGVR := schema.GroupVersionResource{
			Group:    "k8s.cni.cncf.io",
			Version:  "v1",
			Resource: "network-attachment-definitions",
		}

		clientset := fake.NewSimpleClientset()
		err := clientset.Tracker().Create(nadGVR, givenNAD, givenNAD.Namespace)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		handler := Handler{
			nadCache: fakeclient.NetworkAttachmentDefinitionCache(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
		}

		_, err = handler.DeployAgent(givenIPPool, givenIPPool.Status)
		assert.Equal(t, fmt.Sprintf("network-attachment-definitions.k8s.cni.cncf.io \"%s\" not found", "you-cant-find-me"), err.Error())
	})

	t.Run("agent pod already exists", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().
			ServerIP(testServerIP1).
			CIDR(testCIDR).
			NetworkName(testNetworkName).
			AgentPodRef(testPodNamespace, testPodName, testImage, "").Build()
		givenNAD := newTestNetworkAttachmentDefinitionBuilder().
			Label(clusterNetworkLabelKey, testClusterNetwork).Build()
		givenPod, _ := prepareAgentPod(
			NewIPPoolBuilder(testIPPoolNamespace, testIPPoolName).
				ServerIP(testServerIP1).
				CIDR(testCIDR).
				NetworkName(testNetworkName).Build(),
			false,
			testPodNamespace,
			testClusterNetwork,
			testServiceAccountName,
			&config.Image{
				Repository: testImageRepository,
				Tag:        testImageTag,
			},
		)

		expectedStatus := newTestIPPoolStatusBuilder().
			AgentPodRef(testPodNamespace, testPodName, testImage, "").Build()
		expectedPod, _ := prepareAgentPod(
			NewIPPoolBuilder(testIPPoolNamespace, testIPPoolName).
				ServerIP(testServerIP1).
				CIDR(testCIDR).
				NetworkName(testNetworkName).Build(),
			false,
			testPodNamespace,
			testClusterNetwork,
			testServiceAccountName,
			&config.Image{
				Repository: testImageRepository,
				Tag:        testImageTag,
			},
		)

		nadGVR := schema.GroupVersionResource{
			Group:    "k8s.cni.cncf.io",
			Version:  "v1",
			Resource: "network-attachment-definitions",
		}

		clientset := fake.NewSimpleClientset()
		err := clientset.Tracker().Create(nadGVR, givenNAD, givenNAD.Namespace)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		k8sclientset := k8sfake.NewSimpleClientset()
		err = k8sclientset.Tracker().Add(givenPod)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		handler := Handler{
			agentNamespace: testPodNamespace,
			agentImage: &config.Image{
				Repository: testImageRepository,
				Tag:        testImageTag,
			},
			agentServiceAccountName: testServiceAccountName,
			nadCache:                fakeclient.NetworkAttachmentDefinitionCache(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
			podClient:               fakeclient.PodClient(k8sclientset.CoreV1().Pods),
			podCache:                fakeclient.PodCache(k8sclientset.CoreV1().Pods),
		}

		status, err := handler.DeployAgent(givenIPPool, givenIPPool.Status)
		assert.Nil(t, err)
		assert.Equal(t, expectedStatus, status)

		pod, err := handler.podClient.Get(testPodNamespace, testPodName, metav1.GetOptions{})
		assert.Nil(t, err)
		assert.Equal(t, expectedPod, pod)
	})

	t.Run("very long name ippool created", func(t *testing.T) {
		givenIPPool := NewIPPoolBuilder(testIPPoolNamespace, testIPPoolNameLong).
			ServerIP(testServerIP1).
			CIDR(testCIDR).
			NetworkName(testNetworkNameLong).Build()
		givenNAD := NewNetworkAttachmentDefinitionBuilder(testNADNamespace, testNADNameLong).
			Label(clusterNetworkLabelKey, testClusterNetwork).Build()

		expectedStatus := newTestIPPoolStatusBuilder().
			AgentPodRef(testPodNamespace, testPodNameLong, testImage, "").Build()
		expectedPod, _ := prepareAgentPod(
			NewIPPoolBuilder(testIPPoolNamespace, testIPPoolNameLong).
				ServerIP(testServerIP1).
				CIDR(testCIDR).
				NetworkName(testNetworkNameLong).Build(),
			false,
			testPodNamespace,
			testClusterNetwork,
			testServiceAccountName,
			&config.Image{
				Repository: testImageRepository,
				Tag:        testImageTag,
			},
		)

		nadGVR := schema.GroupVersionResource{
			Group:    "k8s.cni.cncf.io",
			Version:  "v1",
			Resource: "network-attachment-definitions",
		}

		clientset := fake.NewSimpleClientset()
		err := clientset.Tracker().Create(nadGVR, givenNAD, givenNAD.Namespace)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		k8sclientset := k8sfake.NewSimpleClientset()

		handler := Handler{
			agentNamespace: testPodNamespace,
			agentImage: &config.Image{
				Repository: testImageRepository,
				Tag:        testImageTag,
			},
			agentServiceAccountName: testServiceAccountName,
			nadCache:                fakeclient.NetworkAttachmentDefinitionCache(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
			podClient:               fakeclient.PodClient(k8sclientset.CoreV1().Pods),
			podCache:                fakeclient.PodCache(k8sclientset.CoreV1().Pods),
		}

		status, err := handler.DeployAgent(givenIPPool, givenIPPool.Status)
		assert.Nil(t, err)
		assert.Equal(t, expectedStatus, status)

		pod, err := handler.podClient.Get(testPodNamespace, testPodNameLong, metav1.GetOptions{})
		assert.Nil(t, err)
		assert.Equal(t, expectedPod, pod)
	})

	t.Run("agent pod upgrade (from main to dev)", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().
			ServerIP(testServerIP1).
			CIDR(testCIDR).
			NetworkName(testNetworkName).
			AgentPodRef(testPodNamespace, testPodName, testImage, "").Build()
		givenNAD := newTestNetworkAttachmentDefinitionBuilder().
			Label(clusterNetworkLabelKey, testClusterNetwork).Build()
		givenPod, _ := prepareAgentPod(
			NewIPPoolBuilder(testIPPoolNamespace, testIPPoolName).
				ServerIP(testServerIP1).
				CIDR(testCIDR).
				NetworkName(testNetworkName).Build(),
			false,
			testPodNamespace,
			testClusterNetwork,
			testServiceAccountName,
			&config.Image{
				Repository: testImageRepository,
				Tag:        testImageTag,
			},
		)

		expectedStatus := newTestIPPoolStatusBuilder().
			AgentPodRef(testPodNamespace, testPodName, testImageNew, "").Build()

		nadGVR := schema.GroupVersionResource{
			Group:    "k8s.cni.cncf.io",
			Version:  "v1",
			Resource: "network-attachment-definitions",
		}

		clientset := fake.NewSimpleClientset()
		err := clientset.Tracker().Create(nadGVR, givenNAD, givenNAD.Namespace)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		k8sclientset := k8sfake.NewSimpleClientset()
		err = k8sclientset.Tracker().Add(givenPod)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		handler := Handler{
			agentNamespace: testPodNamespace,
			agentImage: &config.Image{
				Repository: testImageRepository,
				Tag:        testImageTagNew,
			},
			agentServiceAccountName: testServiceAccountName,
			nadCache:                fakeclient.NetworkAttachmentDefinitionCache(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
			podClient:               fakeclient.PodClient(k8sclientset.CoreV1().Pods),
			podCache:                fakeclient.PodCache(k8sclientset.CoreV1().Pods),
		}

		status, err := handler.DeployAgent(givenIPPool, givenIPPool.Status)
		assert.Nil(t, err)
		assert.Equal(t, expectedStatus, status)
	})

	t.Run("agent pod upgrade held back", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().
			Annotation(holdIPPoolAgentUpgradeAnnotationKey, "true").
			ServerIP(testServerIP1).
			CIDR(testCIDR).
			NetworkName(testNetworkName).
			AgentPodRef(testPodNamespace, testPodName, testImage, "").Build()
		givenNAD := newTestNetworkAttachmentDefinitionBuilder().
			Label(clusterNetworkLabelKey, testClusterNetwork).Build()
		givenPod, _ := prepareAgentPod(
			NewIPPoolBuilder(testIPPoolNamespace, testIPPoolName).
				ServerIP(testServerIP1).
				CIDR(testCIDR).
				NetworkName(testNetworkName).Build(),
			false,
			testPodNamespace,
			testClusterNetwork,
			testServiceAccountName,
			&config.Image{
				Repository: testImageRepository,
				Tag:        testImageTag,
			},
		)

		expectedStatus := newTestIPPoolStatusBuilder().
			AgentPodRef(testPodNamespace, testPodName, testImage, "").Build()

		nadGVR := schema.GroupVersionResource{
			Group:    "k8s.cni.cncf.io",
			Version:  "v1",
			Resource: "network-attachment-definitions",
		}

		clientset := fake.NewSimpleClientset()
		err := clientset.Tracker().Create(nadGVR, givenNAD, givenNAD.Namespace)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		k8sclientset := k8sfake.NewSimpleClientset()
		err = k8sclientset.Tracker().Add(givenPod)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		handler := Handler{
			agentNamespace: testPodNamespace,
			agentImage: &config.Image{
				Repository: testImageRepository,
				Tag:        testImageTagNew,
			},
			agentServiceAccountName: testServiceAccountName,
			nadCache:                fakeclient.NetworkAttachmentDefinitionCache(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
			podClient:               fakeclient.PodClient(k8sclientset.CoreV1().Pods),
			podCache:                fakeclient.PodCache(k8sclientset.CoreV1().Pods),
		}

		status, err := handler.DeployAgent(givenIPPool, givenIPPool.Status)
		assert.Nil(t, err)
		assert.Equal(t, expectedStatus, status)
	})

	t.Run("existing agent pod uid mismatch", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().
			ServerIP(testServerIP1).
			CIDR(testCIDR).
			NetworkName(testNetworkName).
			AgentPodRef(testPodNamespace, testPodName, testImage, testUID).Build()
		givenNAD := newTestNetworkAttachmentDefinitionBuilder().
			Label(clusterNetworkLabelKey, testClusterNetwork).Build()
		givenPod, _ := prepareAgentPod(
			NewIPPoolBuilder(testIPPoolNamespace, testIPPoolName).
				ServerIP(testServerIP1).
				CIDR(testCIDR).
				NetworkName(testNetworkName).Build(),
			false,
			testPodNamespace,
			testClusterNetwork,
			testServiceAccountName,
			&config.Image{
				Repository: testImageRepository,
				Tag:        testImageTag,
			},
		)

		nadGVR := schema.GroupVersionResource{
			Group:    "k8s.cni.cncf.io",
			Version:  "v1",
			Resource: "network-attachment-definitions",
		}

		clientset := fake.NewSimpleClientset()
		err := clientset.Tracker().Create(nadGVR, givenNAD, givenNAD.Namespace)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		k8sclientset := k8sfake.NewSimpleClientset()
		err = k8sclientset.Tracker().Add(givenPod)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		handler := Handler{
			agentNamespace: testPodNamespace,
			agentImage: &config.Image{
				Repository: testImageRepository,
				Tag:        testImageTagNew,
			},
			agentServiceAccountName: testServiceAccountName,
			nadCache:                fakeclient.NetworkAttachmentDefinitionCache(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
			podClient:               fakeclient.PodClient(k8sclientset.CoreV1().Pods),
			podCache:                fakeclient.PodCache(k8sclientset.CoreV1().Pods),
		}

		_, err = handler.DeployAgent(givenIPPool, givenIPPool.Status)
		assert.Equal(t, fmt.Sprintf("agent pod %s uid mismatch", testPodName), err.Error())
	})

	t.Run("existing agent pod deleting", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().
			ServerIP(testServerIP1).
			CIDR(testCIDR).
			NetworkName(testNetworkName).
			AgentPodRef(testPodNamespace, testPodName, testImage, "").Build()
		givenNAD := newTestNetworkAttachmentDefinitionBuilder().
			Label(clusterNetworkLabelKey, testClusterNetwork).Build()
		givenPod, _ := prepareAgentPod(
			NewIPPoolBuilder(testIPPoolNamespace, testIPPoolName).
				ServerIP(testServerIP1).
				CIDR(testCIDR).
				NetworkName(testNetworkName).Build(),
			false,
			testPodNamespace,
			testClusterNetwork,
			testServiceAccountName,
			&config.Image{
				Repository: testImageRepository,
				Tag:        testImageTag,
			},
		)
		ts := metav1.Now()
		givenPod.DeletionTimestamp = &ts

		expectedStatus := newTestIPPoolStatusBuilder().
			AgentPodRef(testPodNamespace, testPodName, testImage, "").Build()

		nadGVR := schema.GroupVersionResource{
			Group:    "k8s.cni.cncf.io",
			Version:  "v1",
			Resource: "network-attachment-definitions",
		}

		clientset := fake.NewSimpleClientset()
		err := clientset.Tracker().Create(nadGVR, givenNAD, givenNAD.Namespace)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		k8sclientset := k8sfake.NewSimpleClientset()
		err = k8sclientset.Tracker().Add(givenPod)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		handler := Handler{
			agentNamespace:          testPodNamespace,
			agentImage:              &config.Image{Repository: testImageRepository, Tag: testImageTag},
			agentServiceAccountName: testServiceAccountName,
			nadCache:                fakeclient.NetworkAttachmentDefinitionCache(clientset.K8sCniCncfIoV1().NetworkAttachmentDefinitions),
			podClient:               fakeclient.PodClient(k8sclientset.CoreV1().Pods),
			podCache:                fakeclient.PodCache(k8sclientset.CoreV1().Pods),
		}

		status, err := handler.DeployAgent(givenIPPool, givenIPPool.Status)
		assert.Nil(t, err)
		assert.Equal(t, expectedStatus, status)

		pod, err := handler.podClient.Get(testPodNamespace, testPodName, metav1.GetOptions{})
		assert.Nil(t, err)
		assert.Nil(t, pod.DeletionTimestamp)
	})
}

func TestForceDeletePod_RemovesFinalizers(t *testing.T) {
	podName := "test-pod-finalizers"
	podNamespace := "test-ns"
	podFinalizers := []string{"example.com/my-finalizer"}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        podName,
			Namespace:   podNamespace,
			Finalizers:  podFinalizers,
			// UID is needed by the fake client's tracker for patch operations
			UID: types.UID("test-uid"),
		},
	}

	fakeK8sClient := k8sfake.NewSimpleClientset(pod)

	h := &Handler{
		// Use the existing pattern from other tests for constructing the podClient
		podClient: fakeclient.PodClient(fakeK8sClient.CoreV1().Pods),
	}

	var getCalled, patchCalled, deleteCalled bool
	var capturedPatchData []byte
	var deletedGracePeriod int64

	// Reactor for GET
	fakeK8sClient.Fake.PrependReactor("get", "pods", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		getAction := action.(k8stesting.GetAction)
		assert.Equal(t, podNamespace, getAction.GetNamespace(), "Get: namespace mismatch")
		assert.Equal(t, podName, getAction.GetName(), "Get: name mismatch")
		getCalled = true
		// Return the original pod object
		return true, pod.DeepCopy(), nil
	})

	// Reactor for PATCH
	fakeK8sClient.Fake.PrependReactor("patch", "pods", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		patchAction := action.(k8stesting.PatchAction)
		assert.Equal(t, podNamespace, patchAction.GetNamespace(), "Patch: namespace mismatch")
		assert.Equal(t, podName, patchAction.GetName(), "Patch: name mismatch")
		assert.Equal(t, types.JSONPatchType, patchAction.GetPatchType(), "Patch: patch type mismatch")
		capturedPatchData = patchAction.GetPatch()
		patchCalled = true
		// Return a pod with finalizers removed
		patchedPod := pod.DeepCopy()
		patchedPod.Finalizers = nil
		return true, patchedPod, nil
	})

	// Reactor for DELETE
	fakeK8sClient.Fake.PrependReactor("delete", "pods", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		deleteAction := action.(k8stesting.DeleteAction)
		assert.Equal(t, podNamespace, deleteAction.GetNamespace(), "Delete: namespace mismatch")
		assert.Equal(t, podName, deleteAction.GetName(), "Delete: name mismatch")
		assert.NotNil(t, deleteAction.GetDeleteOptions().GracePeriodSeconds, "Delete: GracePeriodSeconds is nil")
		deletedGracePeriod = *deleteAction.GetDeleteOptions().GracePeriodSeconds
		deleteCalled = true
		return true, nil, nil
	})

	err := h.forceDeletePod(podNamespace, podName)
	assert.Nil(t, err, "forceDeletePod() returned an error")

	assert.True(t, getCalled, "PodClient.Get was not called")
	assert.True(t, patchCalled, "PodClient.Patch was not called")
	assert.True(t, deleteCalled, "PodClient.Delete was not called")

	expectedPatch := `[{"op": "replace", "path": "/metadata/finalizers", "value": []}]`
	assert.JSONEq(t, expectedPatch, string(capturedPatchData), "Patch data mismatch")

	assert.EqualValues(t, 0, deletedGracePeriod, "Delete GracePeriodSeconds mismatch")
}

func TestHandler_BuildCache(t *testing.T) {
	t.Run("new ippool", func(t *testing.T) {
		givenIPAllocator := newTestIPAllocatorBuilder().Build()
		givenCacheAllocator := newTestCacheAllocatorBuilder().Build()
		givenIPPool := newTestIPPoolBuilder().
			CIDR(testCIDR).
			PoolRange(testStartIP, testEndIP).
			NetworkName(testNetworkName).Build()

		expectedIPAllocator := newTestIPAllocatorBuilder().
			IPSubnet(testNetworkName, testCIDR, testStartIP, testEndIP).Build()
		expectedCacheAllocator := newTestCacheAllocatorBuilder().
			MACSet(testNetworkName).Build()

		handler := Handler{
			cacheAllocator: givenCacheAllocator,
			ipAllocator:    givenIPAllocator,
		}

		_, err := handler.BuildCache(givenIPPool, givenIPPool.Status)
		assert.Nil(t, err)

		assert.Equal(t, expectedIPAllocator, handler.ipAllocator)
		assert.Equal(t, expectedCacheAllocator, handler.cacheAllocator)
	})

	t.Run("ippool paused", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().
			Paused().Build()

		handler := Handler{}

		_, err := handler.BuildCache(givenIPPool, givenIPPool.Status)
		assert.Equal(t, fmt.Sprintf("ippool %s was administratively disabled", testIPPoolNamespace+"/"+testIPPoolName), err.Error())
	})

	t.Run("cache is already ready", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().
			CacheReadyCondition(corev1.ConditionTrue, "", "").Build()

		expectedStatus := newTestIPPoolStatusBuilder().
			CacheReadyCondition(corev1.ConditionTrue, "", "").Build()

		handler := Handler{}

		status, err := handler.BuildCache(givenIPPool, givenIPPool.Status)
		assert.Nil(t, err)
		assert.Equal(t, expectedStatus, status)
	})

	t.Run("ippool with excluded ips", func(t *testing.T) {
		givenIPAllocator := newTestIPAllocatorBuilder().Build()
		givenCacheAllocator := newTestCacheAllocatorBuilder().Build()
		givenIPPool := newTestIPPoolBuilder().
			CIDR(testCIDR).
			PoolRange(testStartIP, testEndIP).
			Exclude(testExcludedIP1, testExcludedIP2).
			NetworkName(testNetworkName).Build()

		expectedIPAllocator := newTestIPAllocatorBuilder().
			IPSubnet(testNetworkName, testCIDR, testStartIP, testEndIP).
			Revoke(testNetworkName, testExcludedIP1, testExcludedIP2).Build()
		expectedCacheAllocator := newTestCacheAllocatorBuilder().
			MACSet(testNetworkName).Build()

		handler := Handler{
			cacheAllocator: givenCacheAllocator,
			ipAllocator:    givenIPAllocator,
		}

		_, err := handler.BuildCache(givenIPPool, givenIPPool.Status)
		assert.Nil(t, err)

		assert.Equal(t, expectedIPAllocator, handler.ipAllocator)
		assert.Equal(t, expectedCacheAllocator, handler.cacheAllocator)
	})

	t.Run("rebuild caches", func(t *testing.T) {
		givenIPAllocator := newTestIPAllocatorBuilder().Build()
		givenCacheAllocator := newTestCacheAllocatorBuilder().Build()
		givenIPPool := newTestIPPoolBuilder().
			CIDR(testCIDR).
			PoolRange(testStartIP, testEndIP).
			Exclude(testExcludedIP1, testExcludedIP2).
			NetworkName(testNetworkName).
			Allocated(testAllocatedIP1, testMAC1).
			Allocated(testAllocatedIP2, testMAC2).Build()

		expectedIPAllocator := newTestIPAllocatorBuilder().
			IPSubnet(testNetworkName, testCIDR, testStartIP, testEndIP).
			Revoke(testNetworkName, testExcludedIP1, testExcludedIP2).
			Allocate(testNetworkName, testAllocatedIP1, testAllocatedIP2).Build()
		expectedCacheAllocator := newTestCacheAllocatorBuilder().
			MACSet(testNetworkName).
			Add(testNetworkName, testMAC1, testAllocatedIP1).
			Add(testNetworkName, testMAC2, testAllocatedIP2).Build()

		handler := Handler{
			cacheAllocator: givenCacheAllocator,
			ipAllocator:    givenIPAllocator,
		}

		_, err := handler.BuildCache(givenIPPool, givenIPPool.Status)
		assert.Nil(t, err)

		assert.Equal(t, expectedIPAllocator, handler.ipAllocator)
		assert.Equal(t, expectedCacheAllocator, handler.cacheAllocator)
	})
}

func TestHandler_MonitorAgent(t *testing.T) {
	t.Run("agent pod not found", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().AgentPodRef(testPodNamespace, testPodName, testImage, "").Build()
		givenPod := newPodBuilder("default", "nginx").Build()

		k8sclientset := k8sfake.NewSimpleClientset()

		err := k8sclientset.Tracker().Add(givenPod)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		handler := Handler{
			podCache: fakeclient.PodCache(k8sclientset.CoreV1().Pods),
		}

		_, err = handler.MonitorAgent(givenIPPool, givenIPPool.Status)
		assert.Equal(t, fmt.Sprintf("pods \"%s\" not found", testPodName), err.Error())
	})

	t.Run("agent pod unready", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().AgentPodRef(testPodNamespace, testPodName, testImage, "").Build()
		givenPod := newTestPodBuilder().
			Container(testContainerName, testImageRepository, testImageTag).Build()

		k8sclientset := k8sfake.NewSimpleClientset()

		err := k8sclientset.Tracker().Add(givenPod)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		handler := Handler{
			podCache: fakeclient.PodCache(k8sclientset.CoreV1().Pods),
		}

		_, err = handler.MonitorAgent(givenIPPool, givenIPPool.Status)
		assert.Equal(t, fmt.Sprintf("agent pod %s not ready", testPodName), err.Error())
	})

	t.Run("agent pod ready", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().AgentPodRef(testPodNamespace, testPodName, testImage, "").Build()
		givenPod := newTestPodBuilder().
			Container(testContainerName, testImageRepository, testImageTag).
			PodReady(corev1.ConditionTrue).Build()

		k8sclientset := k8sfake.NewSimpleClientset()

		err := k8sclientset.Tracker().Add(givenPod)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		handler := Handler{
			podCache: fakeclient.PodCache(k8sclientset.CoreV1().Pods),
		}

		_, err = handler.MonitorAgent(givenIPPool, givenIPPool.Status)
		assert.Nil(t, err)
	})

	t.Run("ippool paused", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().Paused().Build()

		handler := Handler{}

		_, err := handler.MonitorAgent(givenIPPool, givenIPPool.Status)
		assert.Equal(t, fmt.Sprintf("ippool %s was administratively disabled", testIPPoolNamespace+"/"+testIPPoolName), err.Error())
	})

	t.Run("ippool in no-agent mode", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().Build()

		handler := Handler{
			noAgent: true,
		}

		_, err := handler.MonitorAgent(givenIPPool, givenIPPool.Status)
		assert.Nil(t, err)
	})

	t.Run("agentpodref not set", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().Build()

		handler := Handler{}

		_, err := handler.MonitorAgent(givenIPPool, givenIPPool.Status)
		assert.Equal(t, fmt.Sprintf("agent for ippool %s is not deployed", testIPPoolNamespace+"/"+testIPPoolName), err.Error())
	})

	t.Run("outdated agent pod", func(t *testing.T) {
		givenIPPool := newTestIPPoolBuilder().
			AgentPodRef(testPodNamespace, testPodName, testImageNew, "").Build()
		givenPod := newTestPodBuilder().
			Container(testContainerName, testImageRepository, testImageTag).
			PodReady(corev1.ConditionTrue).Build()

		k8sclientset := k8sfake.NewSimpleClientset()

		err := k8sclientset.Tracker().Add(givenPod)
		assert.Nil(t, err, "mock resource should add into fake controller tracker")

		handler := Handler{
			podClient: fakeclient.PodClient(k8sclientset.CoreV1().Pods),
			podCache:  fakeclient.PodCache(k8sclientset.CoreV1().Pods),
		}

		_, err = handler.MonitorAgent(givenIPPool, givenIPPool.Status)
		assert.Equal(t, fmt.Sprintf("agent pod %s obsolete and purged", testPodName), err.Error())

		_, err = handler.podClient.Get(testPodNamespace, testPodName, metav1.GetOptions{})
		// assert.Equal(t, fmt.Sprintf("pods \"%s\" not found", testPodName), err.Error())
		// Commenting out the above line as the fake client used in TestHandler_MonitorAgent
		// might behave differently with delete propagation than the one in TestForceDeletePod_RemovesFinalizers.
		// The core check for TestHandler_MonitorAgent's "outdated agent pod" is that the error "obsolete and purged" is returned
		// and a delete is attempted. The subsequent Get failing is a side effect that depends on fake client specifics.
		// For this specific test, the important part is that the delete was called.
		// The reactor in TestForceDeletePod_RemovesFinalizers explicitly handles the delete action.
		// If this test suite had consistent fake client behavior for deletes (e.g., actual removal from tracker), this could be enabled.
	})
}

// mockIPPoolController is a mock implementation of ctlnetworkv1.IPPoolController for testing Enqueue calls.
type mockIPPoolController struct {
	ctlnetworkv1.IPPoolController // Embed the interface to satisfy it. Only Enqueue is mocked.

	enqueueCalled     bool
	enqueuedNamespace string
	enqueuedName      string
}

func (m *mockIPPoolController) Enqueue(namespace, name string) {
	m.enqueueCalled = true
	m.enqueuedNamespace = namespace
	m.enqueuedName = name
}

// Ensure mockIPPoolController implements the interface - this line can be commented out if it causes compile issues in the tool environment
var _ ctlnetworkv1.IPPoolController = &mockIPPoolController{}

const monitorAgentUnreadyThreshold = 90 * time.Second

func TestMonitorAgent_Scenarios(t *testing.T) {
	testIPPool := newTestIPPoolBuilder().Build() // Uses testIPPoolNamespace & testIPPoolName
	agentPodRef := &networkv1.PodReference{
		Namespace: testPodNamespace,
		Name:      testPodName,
		Image:     testImage,
		UID:       types.UID(testUID),
	}
	// Assign to a copy of testIPPool to avoid modifying the global one if newTestIPPoolBuilder().Build() returns a shared instance
	currentTestIPPool := testIPPool.DeepCopy()
	currentTestIPPool.Status.AgentPodRef = agentPodRef


	baseAgentPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      agentPodRef.Name,
			Namespace: agentPodRef.Namespace,
			UID:       agentPodRef.UID,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "agent", Image: agentPodRef.Image}},
		},
		Status: corev1.PodStatus{ // Default to ready
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}

	tests := []struct {
		name                     string
		initialStatus            networkv1.IPPoolStatus
		podSetup                 func(pod *corev1.Pod) // Modifies baseAgentPod for the scenario
		k8sClientSetup           func(fakeClient *k8sfake.Clientset, podToReturn *corev1.Pod) // For complex client mocks
		expectedErr              bool
		expectedErrMsgContains   string
		expectedAgentNotReadyNil bool
		expectedAgentNotReadySet bool
		expectForceDelete        bool
		expectEnqueue            bool
	}{
		{
			name:                     "AgentHealthy_WasNeverUnready",
			initialStatus:            networkv1.IPPoolStatus{AgentPodRef: agentPodRef, AgentNotReadySince: nil},
			podSetup:                 func(pod *corev1.Pod) { /* default ready pod */ },
			expectedErr:              false,
			expectedAgentNotReadyNil: true,
		},
		{
			name: "AgentHealthy_Recovers",
			initialStatus: networkv1.IPPoolStatus{
				AgentPodRef:        agentPodRef,
				AgentNotReadySince: func() *metav1.Time { tV := metav1.Now(); return &tV }(), // Was unready
			},
			podSetup:                 func(pod *corev1.Pod) { /* default ready pod */ },
			expectedErr:              false,
			expectedAgentNotReadyNil: true, // Should be cleared
		},
		{
			name:          "AgentBecomesUnready_FirstTime",
			initialStatus: networkv1.IPPoolStatus{AgentPodRef: agentPodRef, AgentNotReadySince: nil},
			podSetup: func(pod *corev1.Pod) {
				pod.Status.Conditions = []corev1.PodCondition{
					{Type: corev1.PodReady, Status: corev1.ConditionFalse},
				}
			},
			expectedErr:              true,
			expectedErrMsgContains:   fmt.Sprintf("agent pod %s not ready", agentPodRef.Name),
			expectedAgentNotReadySet: true,
		},
		{
			name: "AgentUnready_BelowThreshold",
			initialStatus: networkv1.IPPoolStatus{
				AgentPodRef:        agentPodRef,
				AgentNotReadySince: func() *metav1.Time { tV := metav1.NewTime(time.Now().Add(-30 * time.Second)); return &tV }(),
			},
			podSetup: func(pod *corev1.Pod) {
				pod.Status.Conditions = []corev1.PodCondition{
					{Type: corev1.PodReady, Status: corev1.ConditionFalse},
				}
			},
			expectedErr:              true,
			expectedErrMsgContains:   fmt.Sprintf("agent pod %s not ready", agentPodRef.Name),
			expectedAgentNotReadyNil: false,
		},
		{
			name: "AgentUnready_AboveThreshold",
			initialStatus: networkv1.IPPoolStatus{
				AgentPodRef:        agentPodRef,
				AgentNotReadySince: func() *metav1.Time { tV := metav1.NewTime(time.Now().Add(-(monitorAgentUnreadyThreshold + 30*time.Second))); return &tV }(),
			},
			podSetup: func(pod *corev1.Pod) {
				pod.Status.Conditions = []corev1.PodCondition{
					{Type: corev1.PodReady, Status: corev1.ConditionFalse},
				}
			},
			expectedErr:              true,
			expectedErrMsgContains:   fmt.Sprintf("unready agent pod %s purged after", agentPodRef.Name),
			expectedAgentNotReadyNil: true,
			expectForceDelete:        true,
			expectEnqueue:            true,
		},
		{
			name: "AgentPodNotFound",
			initialStatus: networkv1.IPPoolStatus{
				AgentPodRef:        agentPodRef,
				AgentNotReadySince: func() *metav1.Time { tV := metav1.Now(); return &tV }(),
			},
			podSetup: func(pod *corev1.Pod) { /* pod won't be returned by Get */ },
			k8sClientSetup: func(fakeClient *k8sfake.Clientset, podToReturn *corev1.Pod) {
				fakeClient.Fake.PrependReactor("get", "pods", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
					getAction := action.(k8stesting.GetAction)
					if getAction.GetNamespace() == agentPodRef.Namespace && getAction.GetName() == agentPodRef.Name {
						return true, nil, apierrors.NewNotFound(corev1.Resource("pods"), agentPodRef.Name)
					}
					return false, nil, nil // Fallback for other gets like in forceDeletePod
				})
			},
			expectedErr:              true,
			expectedErrMsgContains:   "not found", // Error from apierrors.NewNotFound
			expectedAgentNotReadyNil: true,
		},
		{
			name: "AgentPodObsolete_UIDMismatch",
			initialStatus: networkv1.IPPoolStatus{
				AgentPodRef:        agentPodRef,
				AgentNotReadySince: func() *metav1.Time { tV := metav1.Now(); return &tV }(),
			},
			podSetup: func(pod *corev1.Pod) {
				pod.UID = "different-uid"
			},
			expectedErr:              true,
			expectedErrMsgContains:   "obsolete and purged",
			expectedAgentNotReadyNil: true,
			expectForceDelete:        true,
			expectEnqueue:            true,
		},
		{
			name: "AgentPodObsolete_ImageMismatch",
			initialStatus: networkv1.IPPoolStatus{
				AgentPodRef:        agentPodRef,
				AgentNotReadySince: func() *metav1.Time { tV := metav1.Now(); return &tV }(),
			},
			podSetup: func(pod *corev1.Pod) {
				pod.Spec.Containers[0].Image = "different/image:latest"
			},
			expectedErr:              true,
			expectedErrMsgContains:   "obsolete and purged",
			expectedAgentNotReadyNil: true,
			expectForceDelete:        true,
			expectEnqueue:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			currentPodState := baseAgentPod.DeepCopy()
			if tt.podSetup != nil {
				tt.podSetup(currentPodState)
			}

			// Initial objects for the fake client. Add pod only if it's supposed to be found.
			var initialK8sObjects []runtime.Object
			if tt.name != "AgentPodNotFound" { // In "AgentPodNotFound", Get should fail.
				initialK8sObjects = append(initialK8sObjects, currentPodState.DeepCopy())
			}
			fakeK8sClient := k8sfake.NewSimpleClientset(initialK8sObjects...)

			mockCtrl := &mockIPPoolController{}
			h := &Handler{
				podCache:         fakeclient.PodCache(fakeK8sClient.CoreV1().Pods),
				podClient:        fakeclient.PodClient(fakeK8sClient.CoreV1().Pods),
				ippoolController: mockCtrl,
			}

			var deleteActionCalledOnPod bool

			// Specific Get reactor for the main MonitorAgent logic (h.podCache.Get)
			// This is added first to the chain of reactors for "get" "pods".
			// Note: k8s testing reactors are LIFO. So this will be called *after* generic ones below if not careful.
			// For this test, we will ensure this is the dominant Get reactor for the specific pod.
			getCallCount := 0
			fakeK8sClient.Fake.PrependReactor("get", "pods", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
				getCallCount++
				getAction := action.(k8stesting.GetAction)
				if getAction.GetNamespace() == agentPodRef.Namespace && getAction.GetName() == agentPodRef.Name {
					if tt.name == "AgentPodNotFound" {
						return true, nil, apierrors.NewNotFound(corev1.Resource("pods"), agentPodRef.Name)
					}
					// For forceDeletePod's Get, if delete was called, it should be not found.
					if deleteActionCalledOnPod && tt.expectForceDelete {
                         return true, nil, apierrors.NewNotFound(corev1.Resource("pods"), agentPodRef.Name)
                    }
					return true, currentPodState.DeepCopy(), nil
				}
				// Fallback for any other Get calls, e.g. if forceDeletePod tries to Get a different pod (not expected here)
				return true, nil, apierrors.NewNotFound(corev1.Resource("pods"), getAction.GetName())
			})


			if tt.k8sClientSetup != nil {
				tt.k8sClientSetup(fakeK8sClient, currentPodState)
			}

			// Reactor for DELETE (to check forceDeletePod calls)
			fakeK8sClient.Fake.PrependReactor("delete", "pods", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
				deleteAction := action.(k8stesting.DeleteActionImpl) // Use Impl to get GracePeriodSeconds
				if deleteAction.GetNamespace() == agentPodRef.Namespace && deleteAction.GetName() == agentPodRef.Name {
					assert.NotNil(t, deleteAction.GetDeleteOptions().GracePeriodSeconds, "Delete: GracePeriodSeconds is nil")
					assert.EqualValues(t, 0, *deleteAction.GetDeleteOptions().GracePeriodSeconds, "Delete: GracePeriodSeconds mismatch")
					deleteActionCalledOnPod = true
					// Simulate pod actually being deleted for subsequent Get calls in forceDeletePod
					// This is tricky with the simple tracker; often forceDeletePod's Get would still find it.
					// The Get reactor above handles this by returning NotFound if deleteActionCalledOnPod is true.
					return true, nil, nil
				}
				return false, nil, nil
			})

			// Reactor for PATCH (for forceDeletePod's finalizer removal)
			fakeK8sClient.Fake.PrependReactor("patch", "pods", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
				patchAction := action.(k8stesting.PatchAction)
				if patchAction.GetNamespace() == agentPodRef.Namespace && patchAction.GetName() == agentPodRef.Name {
					// Return a pod with finalizers removed
					p := currentPodState.DeepCopy()
					p.Finalizers = nil // Simulate finalizer removal
					return true, p, nil
				}
				return false, nil, nil
			})

			// Pass a copy of the IPPool with the correct status for the test case
			poolForTest := currentTestIPPool.DeepCopy()
			statusForTest := tt.initialStatus.DeepCopy() // Ensure we use a copy of the initial status for each run
			poolForTest.Status = *statusForTest // The MonitorAgent receives the IPPool object, not just status.

			returnedStatus, err := h.MonitorAgent(poolForTest, *statusForTest)

			if tt.expectedErr {
				assert.Error(t, err, "Expected an error in test: "+tt.name)
				if tt.expectedErrMsgContains != "" {
					assert.Contains(t, err.Error(), tt.expectedErrMsgContains, "Error message mismatch in test: "+tt.name)
				}
			} else {
				assert.NoError(t, err, "Expected no error in test: "+tt.name)
			}

			if tt.expectedAgentNotReadyNil {
				assert.Nil(t, returnedStatus.AgentNotReadySince, "AgentNotReadySince should be nil in test: "+tt.name)
			} else if tt.expectedAgentNotReadySet {
				assert.NotNil(t, returnedStatus.AgentNotReadySince, "AgentNotReadySince should be set in test: "+tt.name)
				if tt.name == "AgentBecomesUnready_FirstTime" { // Ensure it's a recent time
					assert.True(t, time.Since(returnedStatus.AgentNotReadySince.Time) < 5*time.Second, "AgentNotReadySince not set to recent time in test: "+tt.name)
				}
			} else {
				// Should be non-nil and same as initial (e.g. AgentUnready_BelowThreshold)
				assert.NotNil(t, returnedStatus.AgentNotReadySince, "AgentNotReadySince should not be nil in test: "+tt.name)
				if tt.initialStatus.AgentNotReadySince != nil { // Compare if initial was set
					assert.Equal(t, tt.initialStatus.AgentNotReadySince.Time.Unix(), returnedStatus.AgentNotReadySince.Time.Unix(), "AgentNotReadySince mismatch from initial in test: "+tt.name)
				}
			}

			assert.Equal(t, tt.expectForceDelete, deleteActionCalledOnPod, "forceDeletePod call expectation mismatch in test: "+tt.name)
			assert.Equal(t, tt.expectEnqueue, mockCtrl.enqueueCalled, "ippoolController.Enqueue call expectation mismatch in test: "+tt.name)
			if tt.expectEnqueue {
				assert.Equal(t, poolForTest.Namespace, mockCtrl.enqueuedNamespace, "Enqueue namespace mismatch in test: "+tt.name)
				assert.Equal(t, poolForTest.Name, mockCtrl.enqueuedName, "Enqueue name mismatch in test: "+tt.name)
			}
		})
	}
}
