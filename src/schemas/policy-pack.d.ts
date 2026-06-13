// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 GuardSpine, Inc.
// Licensed under the Business Source License 1.1. See LICENSE for terms.
// Change License: Apache-2.0. Change Date: see LICENSE.
/**
 * Policy Pack type definitions for @guardspine/kernel.
 * A policy pack defines the rules an evidence bundle is evaluated against.
 */

export interface PolicyPack {
  policy_id: string;
  version: string;
  name: string;
  description?: string;
  rules: PolicyRule[];
  metadata?: Record<string, unknown>;
}

export interface PolicyRule {
  rule_id: string;
  name: string;
  description?: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  condition: PolicyCondition;
}

export interface PolicyCondition {
  /** JSONPath or simple key to evaluate */
  field: string;
  operator: "eq" | "neq" | "gt" | "gte" | "lt" | "lte" | "contains" | "matches" | "exists";
  value?: unknown;
}
