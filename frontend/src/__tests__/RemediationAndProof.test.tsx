import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import { RemediationView } from '../views/RemediationView';
import { ProofConditionsTable } from '../components/ProofConditionsTable';
import type { ProofVerificationItem, RemediationReport } from '../types/api';

describe('RemediationView Component', () => {
  const sampleReport: RemediationReport = {
    repository_path: 'tests/fixtures/nodegoat',
    total_findings_evaluated: 2,
    candidates_generated: 1,
    contradictions_detected: 0,
    candidates: [
      {
        candidate_id: 'cand-1',
        strategy: 'DIRECT_UPGRADE',
        package_name: 'express',
        current_version: '4.16.4',
        target_version: '4.20.0',
        files_changed: ['package.json'],
        dependencies_affected: ['express'],
        api_impact: 'MINIMAL',
        version_impact: 'MINOR',
        closure_status: 'REQUIRES_VERIFICATION',
        confidence_level: 'LOW',
        lockfile_action: 'REGENERATION_REQUIRED',
        closed_advisories_count: 2,
        total_advisories_count: 2,
        closed_paths_count: 0,
        total_paths_count: 1,
        reason: 'Static reachability remains UNKNOWN; verification required.',
        evidence_ids: ['ev-1'],
        preconditions: ['Repository tests pass'],
        expected_effect: 'Resolves all 2 known advisories',
        status: 'PROPOSED',
        simulated_patch: '--- a/package.json\n+++ b/package.json\n- "express": "4.16.4"\n+ "express": "4.20.0"',
      },
    ],
    manifest_patches: { 'package.json': 'patch content' },
    lockfile_regeneration_required: true,
    summary: 'Generated 1 minimum blast-radius candidate.',
    created_at: '2026-10-09T00:00:00Z',
  };

  it('renders deterministic remediation candidate without arbitrary numeric blast radius scores', () => {
    const handleGenerate = vi.fn();
    render(
      <RemediationView
        repositoryPath="tests/fixtures/nodegoat"
        remediationReport={sampleReport}
        onGenerateRemediation={handleGenerate}
        isLoading={false}
      />
    );

    // Component name and version transition
    expect(screen.getByText('express')).toBeInTheDocument();
    expect(screen.getByText('4.16.4')).toBeInTheDocument();
    expect(screen.getByText('4.20.0')).toBeInTheDocument();

    // Strategy & Advisories
    expect(screen.getByText('DIRECT_UPGRADE')).toBeInTheDocument();
    expect(screen.getByText((_content, element) => element?.textContent === '2 / 2 resolved')).toBeInTheDocument();

    // Closure & Confidence
    expect(screen.getByRole('status', { name: /Status: REQUIRES_VERIFICATION/i })).toBeInTheDocument();
    expect(screen.getByText('LOW')).toBeInTheDocument();

    // Verify button exists
    expect(screen.getByRole('button', { name: /Verify Remediation/i })).toBeInTheDocument();

    // Confirm no numeric score values are shown
    expect(screen.queryByText(/blast radius score/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/0\.25/)).not.toBeInTheDocument();
  });
});

describe('ProofConditionsTable Component', () => {
  const sampleProofItem: ProofVerificationItem = {
    candidate: 'cand-12345678',
    target_component: 'express',
    strategy: 'DIRECT_UPGRADE',
    before: {
      phase: 'before',
      repository_identity: 'tests/fixtures/nodegoat',
      component: 'express',
      version: '4.16.4',
      advisories: ['GHSA-express-1', 'GHSA-express-2'],
      verdict: 'UNKNOWN',
      reachability_status: 'UNKNOWN',
      reachable_symbols: ['router.handle'],
      exposure_paths: ['path-1'],
    },
    after: {
      phase: 'after',
      repository_identity: 'tests/fixtures/nodegoat',
      component: 'express',
      version: '4.20.0',
      advisories: [],
      verdict: 'PROVEN_NOT_AFFECTED',
      reachability_status: 'NOT_REACHABLE',
      reachable_symbols: [],
      exposure_paths: [],
    },
    proof_conditions: {
      version_closed: true,
      advisories_closed: true,
      vulnerable_symbol_closed: true,
      exposure_path_closed: false,
      tests_validated: false,
      test_status: 'NOT_EXECUTED',
      test_reason: 'Repository command execution disabled by security policy.',
    },
    evidence: ['ev-proof-1'],
    verification_status: 'REQUIRES_VERIFICATION',
    uncertainty_reason: 'Exposure path severance cannot be verified without lockfile.',
    missing_evidence: 'Regenerated lockfile or runtime probe observation.',
    final_verdict: 'UNKNOWN',
  };

  it('renders before/after snapshots and 5 proof conditions accurately', () => {
    render(<ProofConditionsTable item={sampleProofItem} />);

    // Before/after versions
    expect(screen.getByText('BEFORE REMEDIATION')).toBeInTheDocument();
    expect(screen.getByText('4.16.4')).toBeInTheDocument();
    expect(screen.getByText('AFTER REMEDIATION')).toBeInTheDocument();
    expect(screen.getByText('4.20.0')).toBeInTheDocument();

    // 5 proof conditions
    expect(screen.getByText('Version Closure')).toBeInTheDocument();
    expect(screen.getByText('Advisory Closure')).toBeInTheDocument();
    expect(screen.getByText('Vulnerable Symbol')).toBeInTheDocument();
    expect(screen.getByText('Exposure Path')).toBeInTheDocument();
    expect(screen.getByText('Test Validation')).toBeInTheDocument();

    // Closed vs Unverified states
    expect(screen.getAllByText('✓ CLOSED').length).toBe(3);
    expect(screen.getAllByText('⚠️ UNVERIFIED').length).toBe(1);
    expect(screen.getByText('— NOT EXECUTED')).toBeInTheDocument();

    // Safe execution policy reason
    expect(screen.getByText(/Repository command execution disabled by security policy/i)).toBeInTheDocument();

    // Verification status
    expect(screen.getByRole('status', { name: /Status: REQUIRES_VERIFICATION/i })).toBeInTheDocument();
  });
});
