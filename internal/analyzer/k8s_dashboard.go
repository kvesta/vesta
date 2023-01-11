package analyzer

import (
	"context"
	"log"

	rv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// checkKuberDashboard extra checks Kubernetes dashboard
func (ks *KScanner) checkKuberDashboard() error {
	log.Printf("Begin Dashboard analyzing")

	deploys, err := ks.KClient.
		AppsV1().
		Deployments("kubernetes-dashboard").
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, dp := range deploys.Items {
		if dp.Name != "kubernetes-dashboard" {
			continue
		}
		args := dp.Spec.Template.Spec.Containers[0].Args
		for _, arg := range args {
			if arg == "--enable-skip-login" {
				th := &threat{
					Param:    "Kubernetes-dashboard --args",
					Value:    "--enable-skip-login",
					Type:     "Deployment",
					Describe: "Staring with --enable-skip-login has a potential sensitive data leakage.",
					Severity: "low",
				}

				ks.checkDashboardRBAC(th)

				ks.VulnConfigures = append(ks.VulnConfigures, th)
				break
			}
		}
	}

	return nil
}

func (ks *KScanner) checkDashboardRBAC(th *threat) {
	clrb, err := ks.KClient.
		RbacV1().
		ClusterRoleBindings().
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return
	}
	clr, err := ks.KClient.
		RbacV1().
		ClusterRoles().
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return
	}

	for _, rb := range clrb.Items {

		for _, sub := range rb.Subjects {
			if sub.Kind != "ServiceAccount" || sub.Name != "kubernetes-dashboard" {
				continue
			}

			if ok, tlist := checkMatchingRole(clr.Items, []rv1.Role{}, rb.RoleRef.Name); ok {

				// Check the clusterrole configuration
				severity := tlist[0].Severity
				if severity == "medium" {
					th.Severity = "high"
					th.Describe = "Staring with --enable-skip-login with view permission " +
						"has a sensitive data leakage."
				} else if severity == "high" {
					th.Severity = "critical"
					th.Describe = "Staring with --enable-skip-login with all permission " +
						"will cause a potential container escape."
				}
				return
			}
		}

	}
}
