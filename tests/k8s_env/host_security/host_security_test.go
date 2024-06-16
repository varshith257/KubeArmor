package hostsecurity

import (
	"fmt"
	"time"

	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	// delete all HSPs
	DeleteAllHsp()
})

var _ = AfterSuite(func() {
	// delete all HSPs
	DeleteAllHsp()
})

var _ = Describe("HSP", func() {
	BeforeEach(func() {
		time.Sleep(1 * time.Second)
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllHsp()
		Expect(err).To(BeNil())
		// wait for policy deletion
		time.Sleep(2 * time.Second)
	})

	Describe("Policy Apply", func() {
		Context("File Access Restrictions", func() {
			It("should deny access to restricted files", func() {
				// Apply the Host Security Policy
				err := K8sApplyFile("manifests/hsp-file-access.yaml")
				Expect(err).To(BeNil())

				// Start Kubearmor Logs
				err = KarmorLogStart("policy", "", "File", "")
				Expect(err).To(BeNil())

				// Attempt to access a restricted file
				out, err := ExecCommandHost([]string{"bash", "-c", "cat /etc/shadow"})
				Expect(err).NotTo(BeNil())
				fmt.Printf("---START---\n%s---END---\n", out)
				Expect(out).To(MatchRegexp(".*Permission denied"))

				// Check policy violation alert
				_, alerts, err := KarmorGetLogs(5*time.Second, 1)
				Expect(err).To(BeNil())
				Expect(len(alerts)).To(BeNumerically(">=", 1))
				Expect(alerts[0].PolicyName).To(Equal("test-hsp-policy-file-access"))
				Expect(alerts[0].Action).To(Equal("Block"))
			})

			It("should allow access to permitted files", func() {
				// Apply the Host Security Policy
				err := K8sApplyFile("manifests/hsp-file-access.yaml")
				Expect(err).To(BeNil())

				// Start Kubearmor Logs
				err = KarmorLogStart("policy", "", "File", "")
				Expect(err).To(BeNil())

				// Attempt to access a permitted file
				out, err := ExecCommandHost([]string{"bash", "-c", "cat /etc/hosts"})
				Expect(err).To(BeNil())
				fmt.Printf("---START---\n%s---END---\n", out)
			})
		})

		Context("Network Access Restrictions", func() {
			It("should deny access to restricted network protocols", func() {
				// Apply the Host Security Policy
				err := K8sApplyFile("manifests/hsp-network-access.yaml")
				Expect(err).To(BeNil())

				// Start Kubearmor Logs
				err = KarmorLogStart("policy", "", "Network", "")
				Expect(err).To(BeNil())

				// Attempt to make a connection using a restricted network protocol
				out, err := ExecCommandHost([]string{"bash", "-c", "curl http://example.com"})
				Expect(err).NotTo(BeNil())
				fmt.Printf("---START---\n%s---END---\n", out)
				Expect(out).To(MatchRegexp(".*Permission denied"))

				// Check policy violation alert
				_, alerts, err := KarmorGetLogs(5*time.Second, 1)
				Expect(err).To(BeNil())
				Expect(len(alerts)).To(BeNumerically(">=", 1))
				Expect(alerts[0].PolicyName).To(Equal("test-hsp-policy-network-access"))
				Expect(alerts[0].Action).To(Equal("Block"))
			})

			It("should allow access to permitted network protocols", func() {
				// Apply the Host Security Policy
				err := K8sApplyFile("manifests/hsp-network-access.yaml")
				Expect(err).To(BeNil())

				// Start Kubearmor Logs
				err = KarmorLogStart("policy", "", "Network", "")
				Expect(err).To(BeNil())

				// Attempt to make a connection using a permitted network protocol
				out, err := ExecCommandHost([]string{"bash", "-c", "curl http://allowed-site.com"})
				Expect(err).To(BeNil())
				fmt.Printf("---START---\n%s---END---\n", out)
			})
		})

		Context("Process Execution Restrictions", func() {
			It("should deny execution of restricted processes", func() {
				// Apply the Host Security Policy
				err := K8sApplyFile("manifests/hsp-process-execution.yaml")
				Expect(err).To(BeNil())

				// Start Kubearmor Logs
				err = KarmorLogStart("policy", "", "Process", "")
				Expect(err).To(BeNil())

				// Attempt to execute a restricted process
				out, err := ExecCommandHost([]string{"bash", "-c", "ping -c 1 google.com"})
				Expect(err).NotTo(BeNil())
				fmt.Printf("---START---\n%s---END---\n", out)
				Expect(out).To(MatchRegexp(".*Permission denied"))

				// Check policy violation alert
				_, alerts, err := KarmorGetLogs(5*time.Second, 1)
				Expect(err).To(BeNil())
				Expect(len(alerts)).To(BeNumerically(">=", 1))
				Expect(alerts[0].PolicyName).To(Equal("test-hsp-policy-process-execution"))
				Expect(alerts[0].Action).To(Equal("Block"))
			})

			It("should allow execution of permitted processes", func() {
				// Apply the Host Security Policy
				err := K8sApplyFile("manifests/hsp-process-execution.yaml")
				Expect(err).To(BeNil())

				// Start Kubearmor Logs
				err = KarmorLogStart("policy", "", "Process", "")
				Expect(err).To(BeNil())

				// Attempt to execute a permitted process
				out, err := ExecCommandHost([]string{"bash", "-c", "ls /"})
				Expect(err).To(BeNil())
				fmt.Printf("---START---\n%s---END---\n", out)
			})
		})
	})
})
