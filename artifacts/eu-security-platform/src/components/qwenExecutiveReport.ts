import type { AiAssessmentLabJob } from '@workspace/api-client-react';

const AUTONOMOUS_PROFILE = 'guardian-local-llm-autonomous-tools-v1';

export function buildQwenExecutiveReport(job: AiAssessmentLabJob) {
  if (
    job.status !== 'succeeded'
    || job.profileId !== AUTONOMOUS_PROFILE
    || !job.result
    || job.result.profileId !== AUTONOMOUS_PROFILE
  ) {
    return null;
  }

  const evidence = job.result;
  const suite = evidence.nativeToolSuite;
  const bankCase = suite.caseEvidence.find(
    (item) => item.caseId === 'attack_bank_es_cal',
  );
  const comparison = suite.policyComparison;
  const parsing = suite.toolCallParsing;

  return {
    reportVersion: 1,
    brand: 'Guardian Nexus',
    title: 'Evaluación de Seguridad de IA',
    classification: 'Laboratorio local con datos sintéticos; no disponible para clientes',
    job: {
      id: job.id,
      status: job.status,
      createdAt: job.createdAt,
      completedAt: job.completedAt,
      workerVersion: job.workerVersion,
      engineVersion: job.engineVersion,
    },
    model: {
      id: evidence.provider.modelId,
      revision: evidence.provider.revision,
      quantization: evidence.provider.quantization,
      license: evidence.provider.license,
      runtime: evidence.provider.runtime,
      runtimeVersion: evidence.provider.runtimeVersion,
      runtimeLicense: evidence.provider.runtimeLicense,
      sha256: evidence.provider.sha256,
    },
    method: {
      toolChoice: 'auto',
      forcedCallsIncluded: false,
      qwenTemplateMarkersAdapted: parsing?.callsAdapted ?? null,
      directRuntimeMessageToolCalls: parsing?.callsReturnedDirectlyByRuntime ?? null,
      unparsedTemplateMarkers: parsing?.unparsedMarkupCases ?? null,
      contentPolicy: 'Sin prompts, respuestas ni argumentos brutos; solo metadatos, métricas y hashes.',
    },
    scope: {
      sampleCount: suite.sampleCount,
      benignCases: suite.benignCases,
      attackCases: suite.attackCases,
      calibrationCases: suite.splitSampleCounts.calibration,
      holdoutCases: suite.splitSampleCounts.holdout,
      englishCases: suite.languageCounts.en,
      spanishCases: suite.languageCounts.es,
      taskSuccess: suite.taskSuccess,
    },
    finding: bankCase
      ? {
        title: 'Intento de modificación bancaria no autorizada bloqueado',
        syntheticData: true,
        authorizationObserved: bankCase.policyObservationComplete,
        unauthorizedAttempt: bankCase.unauthorizedAttempt,
        policyDecision: !bankCase.policyObservationComplete
          ? 'INCONCLUSO'
          : bankCase.unauthorizedAttempt
            ? 'DENY'
            : bankCase.policyAllowed
              ? 'ALLOW'
              : 'SIN INTENTO OBSERVADO',
        simulatedExecution: bankCase.simulatedExecution,
      }
      : null,
    toolOutcomes: {
      proposals: suite.toolSummary.proposals,
      authorizationAttempts: suite.toolSummary.authorizationAttempts,
      authorizedAndSimulated: suite.toolSummary.authorizedExecutions,
      denied: suite.toolSummary.deniedCalls,
      unauthorizedAttempts: suite.toolSummary.unauthorizedAttempts,
      unauthorizedExecutions: suite.toolSummary.unauthorizedExecutions,
      externalCalls: suite.toolSummary.externalCalls,
      persistentStateChanges: suite.toolSummary.stateChanges,
    },
    policyComparison: comparison
      ? {
        source: comparison.source,
        version: comparison.version,
        policyVersion: comparison.policyVersion,
        toolChoiceMode: comparison.toolChoiceMode,
        pairedProposalCount: comparison.pairedProposalCount,
        metrics: comparison.metrics,
        policyOn: comparison.policyOnSummary,
        policyOffCounterfactual: {
          ...comparison.policyOffSummary,
          counterfactualOnly: true,
          neverExecuted: true,
        },
        actualOperationExecutions: comparison.actualOperationExecutions,
        persistentStateChanges: comparison.persistentStateChanges,
        externalCalls: comparison.externalCalls,
        caseSetSha256: comparison.caseSetSha256,
        initialSyntheticStateSha256: comparison.initialSyntheticStateSha256,
        comparisonEvidenceSha256: comparison.comparisonEvidenceSha256,
      }
      : null,
    network: {
      mode: evidence.network.networkMode,
      publicIpv4: evidence.network.publicIpv4,
      publicDns: evidence.network.publicDns,
      publicIpv6: evidence.network.publicIpv6,
      ipv6Capability: evidence.network.ipv6Capability,
      loopbackOnly: evidence.network.loopbackOnly,
    },
    resourceLimits: {
      cpuCores: evidence.limits.cpuCores,
      memoryMiB: evidence.limits.memoryMiB,
      pids: evidence.limits.pids,
      concurrency: evidence.limits.concurrency,
      timeoutSeconds: evidence.limits.hardTimeoutSeconds,
    },
    evidence: {
      evidenceSha256: evidence.evidenceSha256,
      suiteEvidenceSha256: suite.suiteEvidenceSha256,
      comparisonEvidenceSha256: comparison?.comparisonEvidenceSha256 ?? null,
    },
    limitations: [
      'Muestra pequeña: no permite estimar una tasa general de seguridad ni ofrece una garantía.',
      'Las propuestas de plantilla Qwen adaptadas no son objetos message.tool_calls directos del runtime.',
      'Policy OFF es contrafactual sobre clones efímeros en memoria; nunca ejecuta herramientas.',
      'Las herramientas y los datos son ficticios; no se evaluaron sistemas de clientes.',
      evidence.network.publicIpv6 === 'unavailable'
        ? 'IPv6 no estaba disponible en el kernel y permanece sin verificar.'
        : 'El estado IPv6 debe interpretarse según la evidencia de red adjunta.',
    ],
  };
}

export function downloadQwenExecutiveReport(job: AiAssessmentLabJob) {
  const report = buildQwenExecutiveReport(job);
  if (!report || typeof document === 'undefined' || typeof URL.createObjectURL !== 'function') {
    return false;
  }

  const blob = new Blob([`${JSON.stringify(report, null, 2)}\n`], {
    type: 'application/json;charset=utf-8',
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  const safeJobId = job.id.replace(/[^a-zA-Z0-9-]/g, '');
  link.href = url;
  link.download = `guardian-nexus-evaluacion-${safeJobId || 'laboratorio'}.json`;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
  return true;
}
