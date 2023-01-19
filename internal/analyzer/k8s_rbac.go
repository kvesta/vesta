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
	rbs, err := ks.KClient.
		RbacV1().
		RoleBindings(ns).
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	rls, err := ks.KClient.
		RbacV1().
		Roles(ns).
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	clr, err := ks.KClient.
		RbacV1().
		ClusterRoles().
		List(context.TODO(), metav1.ListOptions{})
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
						"| rolename: %s | role kind: Role "+
						"| subject kind: %s | subject name: %s | namespace: %s", roleName, ruleName, subKind, subName, ns)

					if subKind == "User" && !strings.HasPrefix(subName, "system:kube-") {

						if config.SeverityMap[th.Severity] < 4 {
							continue
						}

						th.Severity = "warning"
						th.Describe = fmt.Sprintf("Key permission are given to unknown user '%s', "+
							"printing it for checking.", subName)
					}

					if strings.Contains(subName, "unauthenticated") {

						if th.Severity == "medium" {
							th.Severity = "high"
						}

						th.Describe = "Key permission are given and every pod can access it, " +
							"which will cause a potential data leakage."
					}

					ks.VulnConfigures = append(ks.VulnConfigures, th)
				}

			}
		case "ClusterRole":
			if ok, tlist := checkMatchingRole(clr.Items, []rv1.Role{}, ruleName); ok {

				for _, th := range tlist {
					th.Type = "RoleBinding"
					th.Param = fmt.Sprintf("binding name: %s "+
						"| rolename: %s | role kind: ClusterRole "+
						"| subject kind: %s | subject name: %s | namespace: %s", roleName, ruleName, subKind, subName, ns)

					if subKind == "User" && !strings.HasPrefix(subName, "system:kube-") {
						if config.SeverityMap[th.Severity] < 4 {
							continue
						}

						th.Severity = "warning"
						th.Describe = fmt.Sprintf("Key permission are given to unknown user '%s', "+
							"printing it for checking.", subName)
					}

					if strings.Contains(subName, "unauthenticated") {
						
						if th.Severity == "medium" {
							th.Severity = "high"
						}

						th.Describe = "Key permission are given and every pod can access it, " +
							"which will cause a potential data leakage."
					}

					ks.VulnConfigures = append(ks.VulnConfigures, th)
				}

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

			switch sub.Kind {
			case "Group":
				switch sub.Name {
				case "system:serviceaccounts", "system:authenticated", "system:unauthenticated":
					checkBindKing(ruleKind, ruleName, rb.Name, sub.Kind, sub.Name, sub.Namespace)
				default:
					// Case of system:serviceaccounts:<namespace>:<serviceaccount>
					if strings.HasPrefix(sub.Name, "system:serviceaccounts:") {
						if len(strings.Split(sub.Name, ":")) > 3 {
							continue
						}

						roleNs := strings.Split(sub.Name, ":")[2]
						checkBindKing(ruleKind, ruleName, rb.Name, sub.Kind, sub.Name, roleNs)
					}
				}
			case "ServiceAccount":
				if sub.Name != "system:anonymous" && sub.Name != "default" {
					continue
				}

				checkBindKing(ruleKind, ruleName, rb.Name, sub.Kind, sub.Name, sub.Namespace)
			case "User":
				checkBindKing(ruleKind, ruleName, rb.Name, sub.Kind, sub.Name, sub.Namespace)
			}

		}
	}

	return nil
}

func (ks *KScanner) checkClusterBinding() error {
	log.Printf(config.Yellow("Begin ClusterRoleBinding analyzing"))

	clrb, err := ks.KClient.
		RbacV1().
		ClusterRoleBindings().
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	clr, err := ks.KClient.
		RbacV1().
		ClusterRoles().
		List(context.TODO(), metav1.ListOptions{})
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

			switch sub.Kind {
			case "Group":
				switch sub.Name {
				case "system:serviceaccounts", "system:authenticated":
					if ok, tlist := checkMatchingRole(clr.Items, []rv1.Role{}, ruleName); ok {

						for _, th := range tlist {
							th.Type = "ClusterRoleBinding"
							th.Param = fmt.Sprintf("binding name: %s "+
								"| rolename: %s | role kind: ClusterRole "+
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
								"| rolename: %s | role kind: ClusterRole "+
								"| subject kind: %s | subject name: %s | namespace: %s",
								rb.Name, ruleName, sub.Kind, sub.Name, sub.Namespace)
							th.Describe = "Key permission are given and every pod can access it, which will cause a potential container escape."
						}

						ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
					}

				default:
					// Case of system:serviceaccounts:<namespace>:<serviceaccount>
					if strings.HasPrefix(sub.Name, "system:serviceaccounts:") {
						if len(strings.Split(sub.Name, ":")) > 3 {
							continue
						}

						roleNs := strings.Split(sub.Name, ":")[2]
						if ok, tlist := checkMatchingRole(clr.Items, []rv1.Role{}, ruleName); ok {

							for _, th := range tlist {
								th.Type = "ClusterRoleBinding"
								th.Param = fmt.Sprintf("binding name: %s "+
									"| rolename: %s | role kind: ClusterRole "+
									"| subject kind: %s | subject name: %s | namespace: %s",
									rb.Name, ruleName, sub.Kind, sub.Name, roleNs)
							}

							ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
						}

					}
				}
			case "ServiceAccount":
				if sub.Name != "system:anonymous" && sub.Name != "default" {
					continue
				}

				if ok, tlist := checkMatchingRole(clr.Items, []rv1.Role{}, ruleName); ok {
					for _, th := range tlist {
						th.Type = "ClusterRoleBinding"
						th.Param = fmt.Sprintf("binding name: %s "+
							"| rolename: %s | role kind: ClusterRole | "+
							"subject kind: ServiceAccount | "+
							"subject name: %s | namespace: %s", rb.Name, ruleName, sub.Name, sub.Namespace)
					}

					ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
				}
			case "User":
				if strings.HasPrefix(sub.Name, "system:kube-") {
					continue
				}

				if ok, tlist := checkMatchingRole(clr.Items, []rv1.Role{}, ruleName); ok {
					for _, th := range tlist {
						if th.Severity == "medium" {
							continue
						}

						th.Severity = "warning"
						th.Type = "ClusterRoleBinding"
						th.Describe = fmt.Sprintf("Key permission are given to unknown user '%s', "+
							"printing it for checking.", sub.Name)
						th.Param = fmt.Sprintf("binding name: %s "+
							"| rolename: %s | role kind: ClusterRole | "+
							"subject kind: User | subject name: %s | namespace: %s",
							rb.Name, ruleName, sub.Name, sub.Namespace)

						ks.VulnConfigures = append(ks.VulnConfigures, th)
					}

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
			if rul.Verbs[0] == "*" && rul.Resources[0] == "*" {
				th.Value = fmt.Sprintf("verbs:* resources:%s", strings.Join(rul.Resources, ", "))
				th.Severity = "high"
				th.Describe = "All the permission are given to the default service account " +
					"which will cause a potential container escape."
				vuln = true
				tlist = append(tlist, th)
				continue
			}

			if len(rul.Verbs) > 0 {
				// Check whether the default account has the permission of pod control
				th.Severity, th.Describe = RBACVulnTypeJudge(rul.Verbs, rul.Resources)

				if th.Severity == "warning" {
					continue
				}

				th.Value = fmt.Sprintf("verbs: %s | resources: %s",
					strings.Join(rul.Verbs, ", "),
					strings.Join(rul.Resources, ", "))

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

	cfs, err := ks.KClient.
		CoreV1().
		ConfigMaps(ns).
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, cf := range cfs.Items {
		data := cf.Data
		for k, v := range data {
			needCheck := false

			for _, p := range passKey {
				if p.MatchString(k) {
					password = v
					needCheck = true
					break
				}
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
						Param:    fmt.Sprintf("ConfigMap Name: %s Namespace: %s", cf.Name, ns),
						Value:    fmt.Sprintf("%s:%s", k, v),
						Type:     "ConfigMap",
						Describe: fmt.Sprintf("ConfigMap has found weak password: '%s'.", password),
						Severity: "high",
					}

					ks.VulnConfigures = append(ks.VulnConfigures, th)

				case "Medium":
					th := &threat{
						Param: fmt.Sprintf("ConfigMap Name: %s Namespace: %s", cf.Name, ns),
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

	ses, err := ks.KClient.
		CoreV1().
		Secrets(ns).
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, se := range ses.Items {
		data := se.Data

		for k, v := range data {
			needCheck := false

			for _, p := range passKey {
				if p.MatchString(k) {
					needCheck = true
					break
				}
			}

			if needCheck {
				password = string(v)

				switch checkWeakPassword(password) {
				case "Weak":
					th := &threat{
						Param:    fmt.Sprintf("Secret Name: %s Namspace: %s", se.Name, ns),
						Value:    fmt.Sprintf("%s:%s", k, v),
						Type:     "Secret",
						Describe: fmt.Sprintf("Secret has found weak password: '%s'.", password),
						Severity: "high",
					}

					ks.VulnConfigures = append(ks.VulnConfigures, th)

				case "Medium":
					th := &threat{
						Param: fmt.Sprintf("Secret Name: %s Namspace: %s", se.Name, ns),
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

func RBACVulnTypeJudge(rules, resources []string) (string, string) {
	var severity = "warning"
	var description string

	dangerResources := []string{"pods", "deployments", "statefulsets",
		"serviceaccounts"}
	dangerRules := []string{"create", "update", "patch", "delete"}
	sensitiveResources := []string{"secrets", "configmaps"}

	secretLeakage := false

	if resources[0] == "*" {
		severity = "medium"
		goto rulesJudge
	}

	for _, resource := range resources {
		for _, drs := range dangerResources {
			switch {
			case resource == drs:
				severity = "medium"
				break

			case strings.HasPrefix(resource, drs):
				if severity != "warning" {
					severity = "low"
				}
			}
		}

		for _, srs := range sensitiveResources {
			if resource == srs {
				severity = "medium"
				secretLeakage = true
				break
			}
		}
	}

	if rules[0] == "*" {
		switch severity {
		case "medium":
			severity = "high"
			description = "All permissions with key resources given to the default service account, " +
				"which will cause a potential container escape."
		case "low":
			severity = "medium"
			description = "All permissions with some resources are given to the default service account " +
				"which will cause a potential data leakage."
		case "warning":
			severity = "low"
			description = "All permissions with unknown resources are given to the default service account " +
				"which will cause a potential data leakage."
		}

		goto otherJudge
	}
rulesJudge:
	for _, verb := range rules {
		for _, drl := range dangerRules {
			if verb != drl {
				continue
			}

			switch severity {
			case "medium":
				severity = "high"
				description = "Key permissions with key resources given to the default service account, " +
					"which will cause a potential data leakage."
			case "low":
				severity = "medium"
				description = "Key permissions with some resources are given to the default service account " +
					"which will cause a potential data leakage."
			case "warning":
				severity = "low"
				description = "Key permissions with unknown resources are given to the default service account " +
					"which will cause a potential data leakage."
			}
			break
		}
	}

otherJudge:
	if description == "" {
		switch severity {
		case "medium":
			if secretLeakage {
				severity = "high"
				description = "Secret view permission is given to the default service account, " +
					"which will cause a data leakage."

			} else {
				description = "Some permissions with key resources given to the default service account, " +
					"which will cause a potential data leakage."
			}
		case "low":
			description = "Some permissions with some resources are given to the default service account " +
				"which will cause a potential data leakage."
		case "warning":
			description = "Some permissions with unknown resources are given to the default service account " +
				"which will cause a potential data leakage."

		}
	}

	return severity, description
}
