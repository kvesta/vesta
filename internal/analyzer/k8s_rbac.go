package analyzer

import (
	"context"
	"fmt"
	"strings"

	rv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (ks *KScanner) checkClusterBinding() error {
	clrb, err := ks.KClient.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	clr, err := ks.KClient.RbacV1().ClusterRoles().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, rb := range clrb.Items {
		for _, sub := range rb.Subjects {

			// Ignore namespace in while list
			isWhite := false

			for _, ns := range namespaceWhileList {
				if sub.Namespace == ns {
					isWhite = true
					break
				}
			}

			if isWhite || sub.Kind != "ServiceAccount" {
				continue
			}

			if sub.Name == "anonymous" || sub.Name == "default" {

				ruleName := rb.RoleRef.Name
				if ok, tlist := checkMatchingRole(clr.Items, ruleName); ok {

					for _, th := range tlist {
						th.Type = "ClusterRoleBinding"
						th.Param = fmt.Sprintf("binding name: %s "+
							"| rolename: %s | namespace: %s", rb.Name, ruleName, sub.Namespace)
					}

					ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
				}
			}
		}
	}

	return nil
}

func checkMatchingRole(clr []rv1.ClusterRole, ruleName string) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	for _, r := range clr {

		if ruleName != r.Name {
			continue
		}

		for _, rul := range r.Rules {
			if len(rul.Resources) < 1 {
				continue
			}

			th := &threat{}

			// Check whether all permission are given
			if rul.Verbs[0] == "*" {
				th.Value = fmt.Sprintf("verbs:* resources:%s", strings.Join(rul.Resources, ","))
				th.Severity = "high"
				th.Describe = "All the permission are given to the default service account " +
					"which will cause a potential container escape."
				vuln = true
				tlist = append(tlist, th)
				continue
			}

			if len(rul.Verbs) > 0 {
				// Check whether the default account has the permission of pod control
				for _, v := range rul.Verbs {
					if v == "create" || v == "update" ||
						v == "patch" || v == "delete" {
						th.Severity = "high"
						th.Describe = "Key permission are given to the default service account " +
							"which will cause a potential container escape."
						break
					}
				}
				if th.Severity == "" {
					th.Severity = "medium"
					th.Describe = "View permission are given to the default service account " +
						"which will cause a potential data leakage."
				}

				th.Value = fmt.Sprintf("verbs: %s | resources: %s",
					strings.Join(rul.Verbs, ","),
					strings.Join(rul.Resources, ","))

				tlist = append(tlist, th)
				vuln = true
			}
		}
	}
	return vuln, tlist
}
