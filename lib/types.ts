import { z } from 'zod';

/**
 * Attack Pattern Schema
 * Defines the structure for representing attack patterns in the system
 */
export const AttackPatternSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(255),
  description: z.string().max(1000),
  category: z.enum([
    'prompt_injection',
    'token_manipulation',
    'data_exfiltration',
    'model_poisoning',
    'jailbreak',
    'adversarial',
    'other'
  ]),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  tags: z.array(z.string()).default([]),
  examples: z.array(z.string()).default([]),
  createdAt: z.date(),
  updatedAt: z.date(),
});

export type AttackPattern = z.infer<typeof AttackPatternSchema>;

/**
 * Defense Toggle Schema
 * Manages the enable/disable state of specific defense mechanisms
 */
export const DefenseToggleSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(255),
  description: z.string().max(1000),
  enabled: z.boolean().default(true),
  defenseType: z.enum([
    'input_validation',
    'output_filtering',
    'rate_limiting',
    'adversarial_detection',
    'content_filtering',
    'sanitization',
    'other'
  ]),
  config: z.record(z.any()).optional(),
  priority: z.number().int().min(0).max(100),
  createdAt: z.date(),
  updatedAt: z.date(),
});

export type DefenseToggle = z.infer<typeof DefenseToggleSchema>;

/**
 * Attack Check Request Schema
 * Represents a request to check input for potential attacks
 */
export const AttackCheckRequestSchema = z.object({
  id: z.string().uuid(),
  input: z.string().min(1).max(10000),
  context: z.object({
    userId: z.string().optional(),
    sessionId: z.string().optional(),
    ipAddress: z.string().ip().optional(),
    userAgent: z.string().optional(),
    metadata: z.record(z.any()).optional(),
  }).optional(),
  checkTypes: z.array(z.enum([
    'prompt_injection',
    'token_manipulation',
    'data_exfiltration',
    'model_poisoning',
    'jailbreak',
    'all'
  ])).default(['all']),
  enabledDefenses: z.array(z.string().uuid()).optional(),
  timestamp: z.date(),
  requestId: z.string().optional(),
});

export type AttackCheckRequest = z.infer<typeof AttackCheckRequestSchema>;

/**
 * Risk Assessment Schema
 * Contains the results of a risk assessment for a given input
 */
export const RiskAssessmentSchema = z.object({
  id: z.string().uuid(),
  requestId: z.string().optional(),
  overallRiskLevel: z.enum(['critical', 'high', 'medium', 'low', 'none']),
  overallRiskScore: z.number().min(0).max(100),
  detectedPatterns: z.array(z.object({
    patternId: z.string().uuid(),
    patternName: z.string(),
    confidence: z.number().min(0).max(1),
    severity: z.enum(['critical', 'high', 'medium', 'low']),
    details: z.string().optional(),
  })).default([]),
  vulnerabilities: z.array(z.object({
    id: z.string().uuid(),
    type: z.string(),
    description: z.string(),
    affectedDefenses: z.array(z.string().uuid()).optional(),
  })).default([]),
  recommendations: z.array(z.object({
    id: z.string().uuid(),
    title: z.string(),
    description: z.string(),
    priority: z.enum(['critical', 'high', 'medium', 'low']),
    action: z.string(),
  })).default([]),
  processedInput: z.string().optional(),
  executionTime: z.number().min(0),
  timestamp: z.date(),
  analyzedBy: z.string().optional(),
});

export type RiskAssessment = z.infer<typeof RiskAssessmentSchema>;

/**
 * Evaluation Result Schema
 * Represents the complete evaluation result of a security check
 */
export const EvaluationResultSchema = z.object({
  id: z.string().uuid(),
  requestId: z.string(),
  passed: z.boolean(),
  status: z.enum(['passed', 'failed', 'warning', 'error']),
  riskAssessment: RiskAssessmentSchema,
  defensesApplied: z.array(z.object({
    defenseId: z.string().uuid(),
    defenseName: z.string(),
    applied: z.boolean(),
    result: z.enum(['blocked', 'allowed', 'flagged', 'modified']),
    details: z.string().optional(),
  })).default([]),
  blockedReasons: z.array(z.string()).default([]),
  flaggedIssues: z.array(z.object({
    severity: z.enum(['critical', 'high', 'medium', 'low']),
    message: z.string(),
    code: z.string().optional(),
  })).default([]),
  suggestedActions: z.array(z.string()).default([]),
  metadata: z.object({
    totalDefensesEnabled: z.number().int().min(0),
    defensesPassed: z.number().int().min(0),
    defensesFailed: z.number().int().min(0),
    executionTimeMs: z.number().min(0),
  }).optional(),
  evaluatedAt: z.date(),
  evaluatedBy: z.string().optional(),
  version: z.string().default('1.0'),
});

export type EvaluationResult = z.infer<typeof EvaluationResultSchema>;

/**
 * Combined validation schema for batching multiple checks
 */
export const BatchAttackCheckRequestSchema = z.object({
  batchId: z.string().uuid(),
  requests: z.array(AttackCheckRequestSchema).min(1).max(100),
  timestamp: z.date(),
});

export type BatchAttackCheckRequest = z.infer<typeof BatchAttackCheckRequestSchema>;

/**
 * Batch evaluation results
 */
export const BatchEvaluationResultSchema = z.object({
  batchId: z.string().uuid(),
  results: z.array(EvaluationResultSchema),
  totalProcessed: z.number().int().min(0),
  totalPassed: z.number().int().min(0),
  totalFailed: z.number().int().min(0),
  completedAt: z.date(),
});

export type BatchEvaluationResult = z.infer<typeof BatchEvaluationResultSchema>;
