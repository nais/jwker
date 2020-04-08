package utils

import (
	"fmt"
	jwkerv1 "nais.io/navikt/jwker/api/v1"
)

func createSoftwareStatement(jwker *jwkerv1.Jwker, appId AppId) (SoftwareStatement, error) {
	var inbound []string
	var outbound []string
	for _, rule := range jwker.Spec.AccessPolicy.Inbound.Rules {
		cluster, namespace := parseAccessPolicy(rule, appId)
		inbound = append(inbound, fmt.Sprintf("%s:%s:%s", cluster, namespace, rule.Application))
	}
	for _, rule := range jwker.Spec.AccessPolicy.Outbound.Rules {
		cluster, namespace := parseAccessPolicy(rule, appId)
		outbound = append(outbound, fmt.Sprintf("%s:%s:%s", cluster, namespace, rule.Application))
	}
	return SoftwareStatement{
		AppId:                appId.String(),
		AccessPolicyInbound:  inbound,
		AccessPolicyOutbound: outbound,
	}, nil
}

func parseAccessPolicy(rule jwkerv1.AccessPolicyRule, appId AppId) (string, string) {
	cluster := rule.Cluster
	namespace := rule.Namespace
	if cluster == "" {
		cluster = appId.Cluster
	}
	if namespace == "" {
		namespace = appId.Namespace
	}
	return cluster, namespace
}
