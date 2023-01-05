package analyzer

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/kvesta/vesta/config"
	rv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (ks *KScanner) checkRoleBinding(ns string) error {
	rbs, err := ks.KClient.RbacV1().RoleBindings(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	rls, err := ks.KClient.RbacV1().Roles(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	clr, err := ks.KClient.RbacV1().ClusterRoles().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	checkBindKing := func(ruleKind, ruleName, roleName, subKind, subName, ns string) {
		switch ruleKind {
		case "Role":
			if ok, tlist := checkMatchingRole([]rv1.ClusterRole{}, rls.Items, ruleName); ok {

				for _, th := range tlist {
					th.Type = "RoleBinding"
					th.Param = fmt.Sprintf("binding name: %s "+
						"| rolename: %s | kind: Role "+
						"| subject kind: %s | subject name: %s | namespace: %s", roleName, ruleName, subKind, subName, ns)

					if strings.Contains(subName, "unauthenticated") {
						th.Describe = "Key permission are given and every pod can access it, which will cause a potential container escape."
					}
				}

				ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
			}
		case "ClusterRole":
			if ok, tlist := checkMatchingRole(clr.Items, []rv1.Role{}, ruleName); ok {

				for _, th := range tlist {
					th.Type = "RoleBinding"
					th.Param = fmt.Sprintf("binding name: %s "+
						"| rolename: %s | kind: ClusterRole "+
						"| subject kind: %s | subject name: %s |namespace: %s", roleName, ruleName, subKind, subName, ns)

					if strings.Contains(subName, "unauthenticated") {
						th.Describe = "Key permission are given and every pod can access it, which will cause a potential container escape."
					}
				}

				ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
			}
		default:
			// ignore
		}
	}

	for _, rb := range rbs.Items {
		for _, sub := range rb.Subjects {
			// Ignore namespace in while list
			isWhite := false

			for _, wns := range namespaceWhileList {
				if sub.Namespace == wns {
					isWhite = true
					break
				}
			}

			if isWhite {
				continue
			}

			ruleKind := rb.RoleRef.Kind
			ruleName := rb.RoleRef.Name
			if len(sub.Namespace) < 1 {
				sub.Namespace = "all"
			}

			if sub.Kind == "Group" {
				switch sub.Name {
				case "system:serviceaccounts", "system:authenticated", "system:unauthenticated":
					checkBindKing(ruleKind, ruleName, rb.Name, sub.Kind, sub.Name, sub.Namespace)
				default:
					// Case of system:serviceaccounts:<namespace>
					if strings.Contains(sub.Name, "system:serviceaccounts:") {
						checkBindKing(ruleKind, ruleName, rb.Name, sub.Kind, sub.Name, sub.Namespace)
					}
				}
			}

			if sub.Kind == "ServiceAccount" &&
				(sub.Name == "system:anonymous" || sub.Name == "default") {

				checkBindKing(ruleKind, ruleName, rb.Name, sub.Kind, sub.Name, sub.Namespace)

			}

		}
	}

	return nil
}

func (ks *KScanner) checkClusterBinding() error {
	log.Printf(config.Yellow("Begin ClusterRoleBinding analyzing"))

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

			// Skip system:basic-user rolebinding name
			if rb.Name == "system:basic-user" {
				isWhite = true
			}

			if isWhite {
				continue
			}

			ruleName := rb.RoleRef.Name

			if len(sub.Namespace) < 1 {
				sub.Namespace = "all"
			}

			if sub.Kind == "Group" {

				switch sub.Name {
				case "system:serviceaccounts", "system:authenticated":

					if ok, tlist := checkMatchingRole(clr.Items, []rv1.Role{}, ruleName); ok {

						for _, th := range tlist {
							th.Type = "ClusterRoleBinding"
							th.Param = fmt.Sprintf("binding name: %s "+
								"| rolename: %s | kind: ClusterRole "+
								"| subject kind: %s | subject name: %s | namespace: %s", rb.Name, ruleName, sub.Kind, sub.Name, sub.Namespace)
							th.Describe = "Key permission are given to all account, which will cause a potential container escape."
						}

						ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
					}

				case "system:unauthenticated":
					if ok, tlist := checkMatchingRole(clr.Items, []rv1.Role{}, ruleName); ok {

						for _, th := range tlist {
							th.Type = "ClusterRoleBinding"
							th.Param = fmt.Sprintf("binding name: %s "+
								"| rolename: %s | kind: ClusterRole "+
								"| subject kind: %s | subject name: %s | namespace: %s", rb.Name, ruleName, sub.Kind, sub.Name, sub.Namespace)
							th.Describe = "Key permission are given and every pod can access it, which will cause a potential container escape."
						}

						ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
					}

				default:
					// Case of system:serviceaccounts:<namespace>
					if strings.Contains(sub.Name, "system:serviceaccounts:") {
						roleNs := strings.Split(sub.Name, ":")[2]

						if ok, tlist := checkMatchingRole(clr.Items, []rv1.Role{}, ruleName); ok {

							for _, th := range tlist {
								th.Type = "ClusterRoleBinding"
								th.Param = fmt.Sprintf("binding name: %s "+
									"| rolename: %s | kind: ClusterRole "+
									"| subject kind: %s | subject name: %s | namespace: %s", rb.Name, ruleName, sub.Kind, sub.Name, roleNs)
							}

							ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
						}

					}
				}
			}

			if sub.Kind == "ServiceAccount" &&
				(sub.Name == "system:anonymous" || sub.Name == "default") {

				if ok, tlist := checkMatchingRole(clr.Items, []rv1.Role{}, ruleName); ok {

					for _, th := range tlist {
						th.Type = "ClusterRoleBinding"
						th.Param = fmt.Sprintf("binding name: %s "+
							"| rolename: %s | subject kind: ClusterRole | subject name: ServiceAccount | namespace: %s", rb.Name, ruleName, sub.Namespace)
					}

					ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
				}
			}
		}
	}

	return nil
}

func checkMatchingRole(clr []rv1.ClusterRole, rol []rv1.Role, ruleName string) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	checkRule := func(rules []rv1.PolicyRule) bool {

		for _, rul := range rules {
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

		return vuln
	}

	// Check clusterrole
	for _, r := range clr {

		if ruleName != r.Name {
			continue
		}

		vuln = checkRule(r.Rules)

	}

	// Check role
	for _, r := range rol {

		if ruleName != r.Name {
			continue
		}

		vuln = checkRule(r.Rules)
	}

	return vuln, tlist
}

func (ks *KScanner) checkConfigMap(ns string) error {

	var password string

	cfs, err := ks.KClient.CoreV1().ConfigMaps(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, cf := range cfs.Items {
		data := cf.Data
		for k, v := range data {
			needCheck := false

			passKey := regexp.MustCompile(`(?i)password`)
			passKey2 := regexp.MustCompile(`(?i)pwd`)
			if passKey.MatchString(k) || passKey2.MatchString(k) {
				password = v
				needCheck = true
			}

			passUrlMatch := regexp.MustCompile(`\w+\+\w+\://\w+\:(.*)?\@`)
			pass := passUrlMatch.FindStringSubmatch(v)
			if len(pass) > 1 {
				password = pass[1]
				needCheck = true
			}

			if needCheck {
				switch checkWeakPassword(password) {
				case "Weak":
					th := &threat{
						Param:    fmt.Sprintf("ConfigMap Name: %s\nNamespace: %s", cf.Name, ns),
						Value:    fmt.Sprintf("%s:%s", k, v),
						Type:     "ConfigMap",
						Describe: fmt.Sprintf("ConfigMap has found weak password: '%s'.", password),
						Severity: "high",
					}

					ks.VulnConfigures = append(ks.VulnConfigures, th)

				case "Medium":
					th := &threat{
						Param: fmt.Sprintf("ConfigMap Name: %s\nNamespace: %s", cf.Name, ns),
						Value: fmt.Sprintf("%s:%s", k, v),
						Type:  "ConfigMap",
						Describe: fmt.Sprintf("ConfigMap has found password '%s' "+
							"need to be reinforeced.", password),
						Severity: "medium",
					}

					ks.VulnConfigures = append(ks.VulnConfigures, th)
				}
			}

		}
	}

	return nil
}

func (ks *KScanner) checkSecret(ns string) error {

	var password string

	ses, err := ks.KClient.CoreV1().Secrets(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, se := range ses.Items {
		data := se.Data

		for k, v := range data {
			passKey := regexp.MustCompile(`(?i)password`)
			passKey2 := regexp.MustCompile(`(?i)pwd`)

			if passKey.MatchString(k) || passKey2.MatchString(k) {
				password = string(v)

				switch checkWeakPassword(password) {
				case "Weak":
					th := &threat{
						Param:    fmt.Sprintf("Secret Name: %s\nNamspace: %s", se.Name, ns),
						Value:    fmt.Sprintf("%s:%s", k, v),
						Type:     "Secret",
						Describe: fmt.Sprintf("Secret has found weak password: '%s'.", password),
						Severity: "high",
					}

					ks.VulnConfigures = append(ks.VulnConfigures, th)

				case "Medium":
					th := &threat{
						Param: fmt.Sprintf("Secret Name: %s\nNamspace: %s", se.Name, ns),
						Value: fmt.Sprintf("%s:%s", k, v),
						Type:  "Secret",
						Describe: fmt.Sprintf("Secret has found password '%s' "+
							"need to be reinforeced.", password),
						Severity: "medium",
					}

					ks.VulnConfigures = append(ks.VulnConfigures, th)
				}

			}

		}
	}

	return nil
}
