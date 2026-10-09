import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import { FindingDetailView } from '../views/FindingDetailView';
import type { Finding } from '../types/api';

describe('FindingDetailView Component', () => {
  const exposedFinding: Finding = {
    id: 'finding-1',
    vulnerability: {
      id: 'GHSA-296q-j2x6-9328',
      aliases: ['CVE-2021-23337'],
      summary: 'Command Injection in lodash.template',
      details: 'Full details of vulnerability',
      severity: 'HIGH',
      affected_ranges: ['< 4.17.21'],
      fixed_versions: ['4.17.21'],
      vulnerable_symbols: ['template'],
      database_specific: {},
    },
    component: {
      name: 'lodash',
      version: '4.17.19',
      is_direct: true,
      manifest_path: 'package.json',
      lockfile_path: 'package-lock.json',
    },
    verdict: 'PROVEN_EXPOSURE',
    applicability_status: 'AFFECTED',
    source_observation_id: 'obs-1',
    source_artifact_path: 'package-lock.json',
    source: 'OSV_ADVISORY',
    evidence_ids: ['ev-1', 'ev-2'],
    confidence: 1.0,
    created_at: '2026-10-09T00:00:00Z',
    notes: 'Proven reachable from HTTP route',
    reachability: {
      status: 'REACHABLE',
      target_symbol: 'template',
      entry_point: 'POST /render',
      call_site: 'app/routes/index.js:14',
      evidence_path: ['POST /render', 'helper()', 'lodash.template'],
      uncertainty_reason: null,
      missing_evidence: null,
      confidence: 1.0,
      evidence_ids: ['ev-1'],
      metadata: {},
    },
    context: {
      status: 'CONFIRMED',
      source: {
        source_type: 'body',
        expression: 'req.body.template',
        location: { file_path: 'app/routes/index.js', line_number: 12 },
        entry_point: 'POST /render',
      },
      entry_point: 'POST /render',
      sink: 'lodash.template',
      sink_location: { file_path: 'app/routes/index.js', line_number: 14 },
      data_flow_path: ['POST /render', 'req.body.template', 'lodash.template'],
      data_flow_steps: [
        { step_type: 'http_entry', expression: 'POST /render', location: { file_path: 'app/routes/index.js', line_number: 10 }, description: 'HTTP route handler' },
        { step_type: 'input_source', expression: 'req.body.template', location: { file_path: 'app/routes/index.js', line_number: 12 }, description: 'Attacker input parameter' },
        { step_type: 'sink_call', expression: 'lodash.template()', location: { file_path: 'app/routes/index.js', line_number: 14 }, description: 'Vulnerable template sink' },
      ],
      uncertainty_reason: null,
      missing_evidence: null,
      confidence: 1.0,
      evidence_ids: ['ev-2'],
      metadata: {},
    },
    uncertainty_reason: null,
    missing_evidence: null,
  };

  const unknownFinding: Finding = {
    ...exposedFinding,
    id: 'finding-2',
    verdict: 'UNKNOWN',
    uncertainty_reason: 'Dynamic route registration in fastify prevents static AST dispatch verification.',
    missing_evidence: 'Runtime HTTP dispatch showing whether POST /login reaches target.',
    reachability: {
      status: 'UNKNOWN',
      target_symbol: 'authenticate',
      entry_point: null,
      call_site: null,
      evidence_path: [],
      uncertainty_reason: 'Dynamic route registration prevents static dispatch verification.',
      missing_evidence: 'Runtime HTTP dispatch log.',
      confidence: 0.5,
      evidence_ids: [],
      metadata: {},
    },
    context: null,
  };

  it('renders PROVEN_EXPOSURE with Why It Matters and Exposure Path hops', () => {
    const handleBack = vi.fn();
    const handleRemediation = vi.fn();
    const handleProbes = vi.fn();

    render(
      <FindingDetailView
        finding={exposedFinding}
        remediationCandidate={null}
        onBack={handleBack}
        onViewRemediation={handleRemediation}
        onViewProbes={handleProbes}
      />
    );

    // Header info
    expect(screen.getAllByText('lodash').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('GHSA-296q-j2x6-9328').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole('status', { name: /Verdict: PROVEN EXPOSURE/i })).toBeInTheDocument();

    // Why it matters
    expect(screen.getByText(/Proven security exposure/i)).toBeInTheDocument();

    // Exposure path hops
    expect(screen.getByText('Verified Attacker-to-Sink Data Flow Path')).toBeInTheDocument();
    expect(screen.getAllByText('POST /render').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('req.body.template').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('lodash.template()')).toBeInTheDocument();

    // Evidence provenance checks
    expect(screen.getByText(/Exact installed version/i)).toBeInTheDocument();
    expect(screen.getAllByText('4.17.19').length).toBeGreaterThanOrEqual(1);
  });

  it('renders UNKNOWN finding with first-class security warning and probe callout', () => {
    const handleBack = vi.fn();
    const handleRemediation = vi.fn();
    const handleProbes = vi.fn();

    render(
      <FindingDetailView
        finding={unknownFinding}
        remediationCandidate={null}
        onBack={handleBack}
        onViewRemediation={handleRemediation}
        onViewProbes={handleProbes}
      />
    );

    // UNKNOWN security warning
    expect(screen.getByText('UNKNOWN — First-Class Security State')).toBeInTheDocument();
    expect(screen.getByText(/ACSA cannot currently prove whether this finding is reachable/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Dynamic route registration/i).length).toBeGreaterThanOrEqual(1);

    // Action to view targeted probe
    const probeBtn = screen.getByRole('button', { name: /View Targeted Probe Specification/i });
    fireEvent.click(probeBtn);
    expect(handleProbes).toHaveBeenCalledWith('finding-2');
  });
});
