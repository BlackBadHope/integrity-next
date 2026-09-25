[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'SubagentStart', 'Stop', 'SubagentStop')]
    [string]$Event
)

$ErrorActionPreference = 'Stop'
$utf8NoBom = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $utf8NoBom
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom

$ExpectedTools = @(
    'integrity_read_events',
    'integrity_append_event',
    'integrity_turn_memory_open',
    'integrity_turn_memory_close',
    'integrity_turn_memory_gap',
    'integrity_turn_memory_coverage',
    'integrity_home_search',
    'integrity_home_fetch',
    'integrity_context_admission',
    'integrity_context_admission_current_turn',
    'integrity_memory_capabilities',
    'integrity_seed_snapshot',
    'integrity_mind_graph',
    'integrity_architecture_admission',
    'integrity_seed_tasks',
    'integrity_seed_event_uid',
    'integrity_seed_connections',
    'integrity_memory_entity_brief',
    'integrity_memory_link_audit',
    'integrity_seed_replay'
)
$DirectCurrentExpectedTools = @($ExpectedTools | Where-Object {
    $_ -ne 'integrity_context_admission_current_turn'
})
$PreviousExpectedTools = @($DirectCurrentExpectedTools | Where-Object {
    $_ -ne 'integrity_seed_event_uid'
})
$LegacyExpectedTools = @($PreviousExpectedTools | Where-Object {
    $_ -notin @('integrity_memory_entity_brief','integrity_memory_link_audit')
})
$script:Connector = $null
$script:HookVersion = '1.7.2'
$script:LifecycleDeadline = [DateTimeOffset]::UtcNow.AddSeconds(45)
$script:SemanticCadenceMaxAgeSeconds = 3600L
$script:SemanticCadenceMaxActions = 24L
$script:SemanticCadenceMinTimedActions = 3L

function Get-Value {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $Default
    }
    if ($Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
    return $Default
}

function Require-Value {
    param($Object, [string]$Name)
    $value = Get-Value -Object $Object -Name $Name -Default $null
    if ($null -eq $value) { throw ('missing_' + $Name) }
    return $value
}

function Require-Property {
    param($Object, [string]$Name)
    if ($null -eq $Object) { throw ('missing_' + $Name) }
    if ($Object -is [Collections.IDictionary]) {
        if (-not $Object.Contains($Name)) { throw ('missing_' + $Name) }
        return $Object[$Name]
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { throw ('missing_' + $Name) }
    return $property.Value
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Name)
    if ($Actual -ne $Expected) { throw ('mismatch_' + $Name) }
}

function Assert-FalseMap {
    param($Map, [string[]]$Names, [string]$Prefix)
    foreach ($name in $Names) {
        Assert-Equal -Actual ([bool](Require-Value -Object $Map -Name $name)) -Expected $false -Name ($Prefix + '_' + $name)
    }
}

function Get-Sha256 {
    param([string]$Text)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    return [Convert]::ToHexString($hash).ToLowerInvariant()
}

function Test-Property {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $false }
    if ($Object -is [Collections.IDictionary]) { return $Object.Contains($Name) }
    return $Object.PSObject.Properties.Name -contains $Name
}

function Assert-ExactKeys {
    param($Object, [string[]]$Expected, [string]$Name)
    if ($null -eq $Object) { throw ('invalid_' + $Name) }
    $actual = @(
        if ($Object -is [Collections.IDictionary]) {
            $Object.Keys | ForEach-Object { [string]$_ }
        }
        else {
            $Object.PSObject.Properties.Name
        }
    )
    foreach ($key in $Expected) {
        if ($actual -notcontains $key) { throw ('invalid_' + $Name) }
    }
    foreach ($key in $actual) {
        if ($Expected -notcontains $key) { throw ('invalid_' + $Name) }
    }
}

function Test-Digest {
    param($Value)
    return $Value -is [string] -and $Value -match '^sha256:[a-f0-9]{64}$'
}

function Validate-AuthorityContract {
    param($Contract, [string]$ExpectedStatus)
    Assert-ExactKeys -Object $Contract -Expected @(
        'protocol','provider_authority','target_action_authority','coordination','legacy_projection'
    ) -Name 'model_mcp_authority_contract_shape'
    Assert-Equal -Actual ([string](Require-Value -Object $Contract -Name 'protocol')) -Expected 'integrity-guardian/authority-separation/v1' -Name 'model_mcp_authority_contract_protocol'
    $provider = Require-Value -Object $Contract -Name 'provider_authority'
    Assert-ExactKeys -Object $provider -Expected @('provider','scope','execution','production','route','canonical_seed_append') -Name 'model_mcp_provider_authority_shape'
    Assert-Equal -Actual ([string](Require-Value -Object $provider -Name 'provider')) -Expected 'integrity-client-memory' -Name 'model_mcp_provider'
    Assert-Equal -Actual ([string](Require-Value -Object $provider -Name 'scope')) -Expected 'canonical-seed-memory' -Name 'model_mcp_provider_scope'
    Assert-Equal -Actual ([string](Require-Value -Object $provider -Name 'execution')) -Expected 'absent' -Name 'model_mcp_provider_execution'
    Assert-Equal -Actual ([string](Require-Value -Object $provider -Name 'production')) -Expected 'absent' -Name 'model_mcp_provider_production'
    Assert-Equal -Actual ([string](Require-Value -Object $provider -Name 'route')) -Expected 'absent' -Name 'model_mcp_provider_route'
    Assert-Equal -Actual ([string](Require-Value -Object $provider -Name 'canonical_seed_append')) -Expected 'one-use-only' -Name 'model_mcp_provider_append'
    $target = Require-Value -Object $Contract -Name 'target_action_authority'
    Assert-ExactKeys -Object $target -Expected @('decision','authoritative_source','provider_boundary_is_target_denial') -Name 'model_mcp_target_authority_shape'
    Assert-Equal -Actual ([string](Require-Value -Object $target -Name 'decision')) -Expected 'not-evaluated' -Name 'model_mcp_target_decision'
    Assert-Equal -Actual ([string](Require-Value -Object $target -Name 'authoritative_source')) -Expected 'target-specific-action-guard' -Name 'model_mcp_target_source'
    Assert-Equal -Actual ([bool](Require-Property -Object $target -Name 'provider_boundary_is_target_denial')) -Expected $false -Name 'model_mcp_target_denial'
    $coordination = Require-Value -Object $Contract -Name 'coordination'
    Assert-ExactKeys -Object $coordination -Expected @('scope','status','canonical_seed_append_affected','external_target_actions_affected') -Name 'model_mcp_coordination_scope_shape'
    Assert-Equal -Actual ([string](Require-Value -Object $coordination -Name 'scope')) -Expected 'integrity-memory-route' -Name 'model_mcp_coordination_scope'
    Assert-Equal -Actual ([string](Require-Value -Object $coordination -Name 'status')) -Expected $ExpectedStatus -Name 'model_mcp_coordination_status'
    Assert-Equal -Actual ([bool](Require-Property -Object $coordination -Name 'canonical_seed_append_affected')) -Expected $false -Name 'model_mcp_seed_append_effect'
    Assert-Equal -Actual ([bool](Require-Property -Object $coordination -Name 'external_target_actions_affected')) -Expected $false -Name 'model_mcp_external_target_effect'
    $legacy = Require-Value -Object $Contract -Name 'legacy_projection'
    Assert-ExactKeys -Object $legacy -Expected @('production_authority','semantics','deprecated','replacement') -Name 'model_mcp_legacy_authority_shape'
    Assert-Equal -Actual ([bool](Require-Property -Object $legacy -Name 'production_authority')) -Expected $false -Name 'model_mcp_legacy_production_authority'
    Assert-Equal -Actual ([string](Require-Value -Object $legacy -Name 'semantics')) -Expected 'memory-provider-does-not-grant-production-authority' -Name 'model_mcp_legacy_semantics'
    Assert-Equal -Actual ([bool](Require-Property -Object $legacy -Name 'deprecated')) -Expected $true -Name 'model_mcp_legacy_deprecated'
    Assert-Equal -Actual ([string](Require-Value -Object $legacy -Name 'replacement')) -Expected 'authority_contract.provider_authority.production' -Name 'model_mcp_legacy_replacement'
}

function Validate-ArchitecturePresentation {
    param($Envelope, $MindReceipt)
    if ($null -eq $Envelope) { throw 'model_mcp_architecture_envelope_invalid' }
    $protocol = [string](Require-Value -Object $Envelope -Name 'protocol')
    if ($protocol -eq 'integrity-client-memory-mcp/v3/architecture-unavailable/v1') {
        Assert-ExactKeys -Object $Envelope -Expected @(
            'protocol','outcome','failure_layer','reason_digest','canonical_writes','production_authority'
        ) -Name 'model_mcp_architecture_unavailable_shape'
        $writes = Require-Property -Object $Envelope -Name 'canonical_writes'
        if (
            [string](Require-Value -Object $Envelope -Name 'outcome') -ne 'unavailable' -or
            [string](Require-Value -Object $Envelope -Name 'failure_layer') -ne 'write-plane-admission' -or
            -not (Test-Digest (Require-Value -Object $Envelope -Name 'reason_digest')) -or
            $writes -is [bool] -or $writes -isnot [long] -or $writes -ne 0 -or
            (Require-Property -Object $Envelope -Name 'production_authority') -isnot [bool] -or
            [bool](Require-Property -Object $Envelope -Name 'production_authority')
        ) { throw 'model_mcp_architecture_unavailable_invalid' }
        return $false
    }
    Assert-Equal -Actual $protocol -Expected 'integrity-client-memory-mcp/v3/architecture-capsule/v1' -Name 'model_mcp_architecture_protocol'
    Assert-ExactKeys -Object $Envelope -Expected @(
        'protocol','architecture','custody','source_architecture_digest','complete','home_record_count','production_authority'
    ) -Name 'model_mcp_architecture_capsule_shape'
    $complete = Require-Property -Object $Envelope -Name 'complete'
    $homeCount = Require-Property -Object $Envelope -Name 'home_record_count'
    $authority = Require-Property -Object $Envelope -Name 'production_authority'
    if (
        -not (Test-Digest (Require-Value -Object $Envelope -Name 'source_architecture_digest')) -or
        $complete -isnot [bool] -or [bool]$complete -or
        $homeCount -is [bool] -or $homeCount -isnot [long] -or $homeCount -ne 0 -or
        $authority -isnot [bool] -or [bool]$authority
    ) { throw 'model_mcp_architecture_capsule_boundary_invalid' }

    $architecture = Require-Value -Object $Envelope -Name 'architecture'
    Assert-ExactKeys -Object $architecture -Expected @('admission_id','summary') -Name 'model_mcp_architecture_shape'
    $architectureId = Require-Value -Object $architecture -Name 'admission_id'
    if (-not (Test-Digest $architectureId)) { throw 'model_mcp_architecture_digest_invalid' }
    $summary = Require-Value -Object $architecture -Name 'summary'
    $summaryFields = @(
        'mind_admission_receipt_id','concept_recovery_digest','coordination_digest',
        'coordination_stop_required','route_disposition','ledger_event_digest',
        'checkpoint_digest','atlas_projection_digest','connectome_compilation_id','synapse_plan_id'
    )
    Assert-ExactKeys -Object $summary -Expected $summaryFields -Name 'model_mcp_architecture_summary_shape'
    foreach ($field in @(
        'mind_admission_receipt_id','concept_recovery_digest','coordination_digest',
        'ledger_event_digest','checkpoint_digest','atlas_projection_digest',
        'connectome_compilation_id','synapse_plan_id'
    )) {
        if (-not (Test-Digest (Require-Value -Object $summary -Name $field))) {
            throw 'model_mcp_architecture_digest_invalid'
        }
    }
    $stopRequired = Require-Property -Object $summary -Name 'coordination_stop_required'
    if ($stopRequired -isnot [bool]) { throw 'model_mcp_architecture_stop_invalid' }
    $expectedRoute = $(if ([bool]$stopRequired) { 'stopped' } else { 'ready' })
    if (
        [string](Require-Value -Object $summary -Name 'mind_admission_receipt_id') -ne [string](Require-Value -Object $MindReceipt -Name 'receipt_id') -or
        [string](Require-Value -Object $summary -Name 'concept_recovery_digest') -ne [string](Require-Value -Object $MindReceipt -Name 'concept_recovery_digest') -or
        [string](Require-Value -Object $summary -Name 'coordination_digest') -ne [string](Require-Value -Object $MindReceipt -Name 'coordination_digest') -or
        [bool]$stopRequired -ne [bool](Require-Property -Object $MindReceipt -Name 'coordination_stop_required') -or
        [string](Require-Value -Object $summary -Name 'route_disposition') -ne $expectedRoute
    ) { throw 'model_mcp_architecture_mind_binding_invalid' }

    $custody = Require-Value -Object $Envelope -Name 'custody'
    Assert-ExactKeys -Object $custody -Expected @(
        'receipt_id','architecture_admission_id','mind_admission_receipt_id','write_status',
        'checkpoint','home_record_count','production_authority'
    ) -Name 'model_mcp_architecture_custody_shape'
    $checkpoint = Require-Value -Object $custody -Name 'checkpoint'
    Assert-ExactKeys -Object $checkpoint -Expected @('checkpoint_id','root_digest','tree_size') -Name 'model_mcp_architecture_checkpoint_shape'
    $custodyHome = Require-Property -Object $custody -Name 'home_record_count'
    $custodyAuthority = Require-Property -Object $custody -Name 'production_authority'
    $treeSize = Require-Property -Object $checkpoint -Name 'tree_size'
    if (
        -not (Test-Digest (Require-Value -Object $custody -Name 'receipt_id')) -or
        [string](Require-Value -Object $custody -Name 'architecture_admission_id') -ne [string]$architectureId -or
        [string](Require-Value -Object $custody -Name 'mind_admission_receipt_id') -ne [string](Require-Value -Object $MindReceipt -Name 'receipt_id') -or
        [string](Require-Value -Object $custody -Name 'write_status') -notin @('recorded','already-recorded') -or
        $custodyHome -is [bool] -or $custodyHome -isnot [long] -or $custodyHome -ne 0 -or
        $custodyAuthority -isnot [bool] -or [bool]$custodyAuthority -or
        [string](Require-Value -Object $checkpoint -Name 'checkpoint_id') -ne 'checkpoint:medor-architecture-custody' -or
        -not (Test-Digest (Require-Value -Object $checkpoint -Name 'root_digest')) -or
        $treeSize -is [bool] -or $treeSize -isnot [long] -or $treeSize -lt 1
    ) { throw 'model_mcp_architecture_custody_invalid' }
    return $true
}

function Get-NegotiatedContextProtocol {
    param($Context, [string]$RequestedProtocol)
    if ($RequestedProtocol -notin @(
        'integrity-client-memory-mcp/v3/context-admission/v1',
        'integrity-client-memory-mcp/v3/context-admission/v2'
    )) { throw 'model_mcp_context_presentation_not_bound' }
    $capabilities = Require-Value -Object $Context -Name 'capabilities'
    $facade = Require-Value -Object $capabilities -Name 'facade'
    $contractVersion = [string](Require-Value -Object $capabilities -Name 'contract_version')
    $serverVersion = [string](Require-Value -Object $facade -Name 'server_version')
    if ($contractVersion -eq '1.5.0' -and $serverVersion -eq '2.6.0') {
        return 'integrity-client-memory-mcp/v3/context-admission/v1'
    }
    $identity = $contractVersion + '/' + $serverVersion
    if ($identity -notin @('1.6.0/2.7.0','1.7.0/2.8.0','1.8.0/2.9.0','1.9.0/2.10.0')) {
        throw 'model_mcp_contract_identity_invalid'
    }
    $session = Require-Value -Object $facade -Name 'session_admission'
    $presentation = Require-Value -Object $session -Name 'context_presentation'
    Assert-ExactKeys -Object $presentation -Expected @(
        'default_protocol','supported_protocols','legacy_fixed_selector'
    ) -Name 'model_mcp_context_capability_shape'
    Assert-Equal -Actual ([string](Require-Value -Object $presentation -Name 'default_protocol')) -Expected 'integrity-client-memory-mcp/v3/context-admission/v2' -Name 'model_mcp_context_capability_default'
    Assert-Equal -Actual ([string](Require-Value -Object $presentation -Name 'legacy_fixed_selector')) -Expected 'explicit-limit' -Name 'model_mcp_context_capability_legacy'
    $supported = @(Require-Value -Object $presentation -Name 'supported_protocols')
    if (
        $supported.Count -ne 2 -or
        [string]$supported[0] -ne 'integrity-client-memory-mcp/v3/context-admission/v2' -or
        [string]$supported[1] -ne 'integrity-client-memory-mcp/v3/context-admission/v1'
    ) { throw 'model_mcp_context_capability_supported_invalid' }
    if ($identity -eq '1.9.0/2.10.0') {
        Validate-AuthorityContract -Contract (Require-Value -Object $capabilities -Name 'authority_contract') -ExpectedStatus 'not-evaluated'
    }
    return $RequestedProtocol
}

function Validate-ContextPresentation {
    param($Context, [string]$ExpectedProtocol)
    $protocol = [string](Require-Value -Object $Context -Name 'protocol')
    Assert-Equal -Actual $protocol -Expected $ExpectedProtocol -Name 'model_mcp_context_presentation'
    if ($protocol -match '/context-admission/v1$') { return $null }
    Assert-Equal -Actual $protocol -Expected 'integrity-client-memory-mcp/v3/context-admission/v2' -Name 'model_mcp_context_protocol'
    Assert-Equal -Actual ([string](Require-Value -Object $Context -Name 'presentation_mode')) -Expected 'adaptive' -Name 'model_mcp_context_mode'
    $mindEnvelope = Require-Value -Object $Context -Name 'mind'
    $mindReceipt = Require-Value -Object $mindEnvelope -Name 'admission_receipt'
    $capsule = Require-Value -Object $mindEnvelope -Name 'mind'
    $selection = Require-Value -Object $mindEnvelope -Name 'selection_receipt'
    Assert-Equal -Actual ([string](Require-Value -Object $capsule -Name 'protocol')) -Expected 'integrity-client-memory-mcp/v3/context-capsule/v1' -Name 'model_mcp_context_capsule_protocol'
    Assert-Equal -Actual ([string](Require-Value -Object $capsule -Name 'memory_source')) -Expected 'canonical-seed-action-log' -Name 'model_mcp_context_capsule_source'
    Assert-Equal -Actual ([long](Require-Value -Object $capsule -Name 'home_record_count')) -Expected 0 -Name 'model_mcp_context_capsule_home'
    Assert-Equal -Actual ([bool](Require-Value -Object $capsule -Name 'production_authority')) -Expected $false -Name 'model_mcp_context_capsule_authority'
    $sourceProjection = Require-Value -Object $capsule -Name 'source_projection'
    Assert-Equal -Actual ([bool](Require-Value -Object $sourceProjection -Name 'complete')) -Expected $false -Name 'model_mcp_context_capsule_complete'
    $projectionDigest = [string](Require-Value -Object $mindReceipt -Name 'projection_digest')
    if ($projectionDigest -notmatch '^sha256:[a-f0-9]{64}$') { throw 'model_mcp_projection_digest_invalid' }
    Assert-Equal -Actual ([string](Require-Value -Object $sourceProjection -Name 'projection_digest')) -Expected $projectionDigest -Name 'model_mcp_context_source_projection'
    Assert-Equal -Actual ([string](Require-Value -Object $selection -Name 'protocol')) -Expected 'integrity-client-memory-mcp/v3/adaptive-context-selection/v1' -Name 'model_mcp_context_selection_protocol'
    Assert-Equal -Actual ([string](Require-Value -Object $selection -Name 'mode')) -Expected 'adaptive' -Name 'model_mcp_context_selection_mode'
    Assert-Equal -Actual ([string](Require-Value -Object $selection -Name 'policy_version')) -Expected 'adaptive-context-v1' -Name 'model_mcp_context_selection_policy'
    $stopReason = [string](Require-Value -Object $selection -Name 'stop_reason')
    if ($stopReason -notin @('bounded-projection-complete','candidate-cap-reached','byte-budget-exhausted')) { throw 'model_mcp_context_selection_stop_reason_invalid' }
    Assert-Equal -Actual ([bool](Require-Value -Object $selection -Name 'truncated')) -Expected $true -Name 'model_mcp_context_selection_truncated'
    [void](Require-Value -Object $selection -Name 'candidates_truncated')
    Assert-Equal -Actual ([string](Require-Value -Object $selection -Name 'source_projection_digest')) -Expected $projectionDigest -Name 'model_mcp_context_selection_source'
    Assert-Equal -Actual ([long](Require-Value -Object $selection -Name 'home_record_count')) -Expected 0 -Name 'model_mcp_context_selection_home'
    Assert-Equal -Actual ([bool](Require-Value -Object $selection -Name 'production_authority')) -Expected $false -Name 'model_mcp_context_selection_authority'
    $maxContextBytes = [long](Require-Value -Object $selection -Name 'max_context_bytes')
    $capsuleBytes = [long](Require-Value -Object $selection -Name 'capsule_bytes')
    $maxCandidates = [long](Require-Value -Object $selection -Name 'max_candidates')
    $candidateCap = [long](Require-Value -Object $selection -Name 'transport_candidate_cap')
    if ($maxContextBytes -lt 8192 -or $maxContextBytes -gt 262144 -or $capsuleBytes -lt 1 -or $capsuleBytes -gt $maxContextBytes -or $maxCandidates -lt 1 -or $maxCandidates -gt 50 -or $candidateCap -lt 1 -or $candidateCap -gt $maxCandidates) {
        throw 'model_mcp_context_selection_bounds_invalid'
    }
    $sourceProjectionBytes = [long](Require-Value -Object $selection -Name 'source_projection_bytes')
    $intentTermCount = [long](Require-Value -Object $selection -Name 'intent_term_count')
    if ($sourceProjectionBytes -lt 1 -or $intentTermCount -lt 0) { throw 'model_mcp_context_selection_counts_invalid' }
    [void](Require-Value -Object $selection -Name 'available_candidates')
    [void](Require-Value -Object $selection -Name 'selected_candidates')
    $capsuleDigest = [string](Require-Value -Object $selection -Name 'capsule_digest')
    if ($capsuleDigest -notmatch '^sha256:[a-f0-9]{64}$') { throw 'model_mcp_context_capsule_digest_invalid' }
    $receiptId = [string](Require-Value -Object $selection -Name 'receipt_id')
    if ($receiptId -notmatch '^sha256:[a-f0-9]{64}$') { throw 'model_mcp_context_selection_receipt_invalid' }
    [void](Validate-ArchitecturePresentation -Envelope (Require-Value -Object $Context -Name 'architecture') -MindReceipt $mindReceipt)
    $capabilities = Require-Value -Object $Context -Name 'capabilities'
    $identity = [string](Require-Value -Object $capabilities -Name 'contract_version') + '/' + [string](Require-Value -Object (Require-Value -Object $capabilities -Name 'facade') -Name 'server_version')
    if ($identity -eq '1.9.0/2.10.0') {
        Validate-AuthorityContract -Contract (Require-Value -Object (Require-Value -Object $Context -Name 'snapshot') -Name 'authority_contract') -ExpectedStatus 'not-evaluated'
        $coordinationStatus = $(if ([bool](Require-Value -Object $mindReceipt -Name 'coordination_stop_required')) { 'stopped' } else { 'ready' })
        Validate-AuthorityContract -Contract (Require-Value -Object $Context -Name 'authority_contract') -ExpectedStatus $coordinationStatus
    }
    return $selection
}

function Get-SemanticCadence {
    param([Collections.IDictionary]$State)
    if (-not [bool](Get-Value -Object $State -Name 'semantic_checkpoint_open' -Default $false)) {
        return @{ open = $false; due = $false; age_seconds = 0L; actions = 0L; state_invalid = $false }
    }
    $actions = 0L
    $actionsValid = [long]::TryParse(
        [string](Get-Value -Object $State -Name 'semantic_checkpoint_actions' -Default ''),
        [ref]$actions
    ) -and $actions -ge 1
    $started = [DateTimeOffset]::MinValue
    $startedValid = [DateTimeOffset]::TryParse(
        [string](Get-Value -Object $State -Name 'semantic_checkpoint_started_utc' -Default ''),
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$started
    )
    if (-not $actionsValid -or -not $startedValid) {
        return @{
            open = $true
            due = $true
            age_seconds = $script:SemanticCadenceMaxAgeSeconds
            actions = $(if ($actionsValid) { $actions } else { 1L })
            state_invalid = $true
        }
    }
    $ageSeconds = [long][Math]::Max(
        0,
        [Math]::Floor(([DateTimeOffset]::UtcNow - $started.ToUniversalTime()).TotalSeconds)
    )
    $mutationSeen = [bool](Get-Value -Object $State -Name 'semantic_checkpoint_mutation_seen' -Default $false)
    $timedWork = $mutationSeen -or $actions -ge $script:SemanticCadenceMinTimedActions
    return @{
        open = $true
        due = ($actions -ge $script:SemanticCadenceMaxActions) -or (
            $timedWork -and $ageSeconds -ge $script:SemanticCadenceMaxAgeSeconds
        )
        age_seconds = $ageSeconds
        actions = $actions
        mutation_seen = $mutationSeen
        state_invalid = $false
    }
}

function Start-SemanticProgress {
    param(
        [Collections.IDictionary]$State,
        [string]$Tool,
        [bool]$Mutation
    )
    if (-not [bool](Get-Value -Object $State -Name 'semantic_checkpoint_open' -Default $false)) {
        $State['semantic_checkpoint_open'] = $true
        $State['semantic_checkpoint_started_utc'] = [DateTimeOffset]::UtcNow.ToString('o')
        $State['semantic_checkpoint_actions'] = 0L
        $State['semantic_checkpoint_mutation_seen'] = $false
    }
    $actions = 0L
    if (-not [long]::TryParse([string](Get-Value -Object $State -Name 'semantic_checkpoint_actions' -Default '0'), [ref]$actions) -or $actions -lt 0) {
        $actions = $script:SemanticCadenceMaxActions
    }
    $State['semantic_checkpoint_actions'] = [Math]::Min($actions + 1L, 1000000L)
    $State['semantic_checkpoint_mutation_seen'] = [bool](
        [bool](Get-Value -Object $State -Name 'semantic_checkpoint_mutation_seen' -Default $false) -or $Mutation
    )
    $State['semantic_checkpoint_last_tool'] = $(if ($Tool.Length -gt 256) { $Tool.Substring(0, 256) } else { $Tool })
    return Get-SemanticCadence -State $State
}

function Close-SemanticCheckpoint {
    param([Collections.IDictionary]$State, [long]$EventId)
    $State['semantic_checkpoint_open'] = $false
    $State['semantic_checkpoint_actions'] = 0L
    $State['semantic_checkpoint_mutation_seen'] = $false
    $State['semantic_checkpoint_event_id'] = $EventId
    $State['semantic_checkpoint_closed_utc'] = [DateTimeOffset]::UtcNow.ToString('o')
    [void]$State.Remove('semantic_checkpoint_started_utc')
    [void]$State.Remove('semantic_checkpoint_last_tool')
    [void]$State.Remove('semantic_checkpoint_notice_key')
}

function Test-NewSemanticNotice {
    param([Collections.IDictionary]$State)
    if (-not [bool](Get-SemanticCadence -State $State).due) { return $false }
    $disposition = if (Test-AppendReady -State $State) { 'ready' }
        elseif ([string](Get-Value -Object $State -Name 'append_outcome' -Default '') -eq 'unknown-outcome') { 'unknown' }
        elseif ([bool](Get-Value -Object $State -Name 'append_attempted' -Default $false)) { 'spent' }
        else { 'unavailable' }
    $key = [string](Get-Value -Object $State -Name 'semantic_checkpoint_started_utc' -Default '') + ':' + $disposition
    if ([string](Get-Value -Object $State -Name 'semantic_checkpoint_notice_key' -Default '') -eq $key) { return $false }
    $State['semantic_checkpoint_notice_key'] = $key
    return $true
}

function Get-LifecycleRemainingMilliseconds {
    param([int]$Maximum = 35000)
    $remaining = [int][Math]::Floor(($script:LifecycleDeadline - [DateTimeOffset]::UtcNow).TotalMilliseconds)
    if ($remaining -le 0) { throw 'lifecycle_deadline_exhausted' }
    return [Math]::Min($Maximum, $remaining)
}

function Get-SemanticContext {
    param([Collections.IDictionary]$State)
    $cadence = Get-SemanticCadence -State $State
    if (-not [bool]$cadence.open) {
        return 'SEMANTIC CADENCE CLEAR: event-per-turn=false; create a Seed event only for a durable decision, result or checkpoint.'
    }
    $disposition = if ([bool]$cadence.due) { 'OVERDUE' } else { 'OPEN' }
    $appendReady = Test-AppendReady -State $State
    $instruction = if ([bool]$cadence.due -and $appendReady) {
        'ADVISORY ONLY: preserve progress in the existing local checkpoint; cadence does not require a canonical append. Reserve the one append attempt for a durable result. Mandatory prior ChangeIntent remains separately required.'
    } elseif ([bool]$cadence.due -and [string](Get-Value -Object $State -Name 'append_outcome' -Default '') -eq 'unknown-outcome') {
        'ADVISORY ONLY: prior append outcome is unknown; continue work and preserve the checkpoint debt. Do not retry; reconcile event_uid.'
    } elseif ([bool]$cadence.due -and [bool](Get-Value -Object $State -Name 'append_attempted' -Default $false)) {
        'ADVISORY ONLY: the current turn already used its one append attempt; continue work and preserve the checkpoint debt for a later admitted turn. Do not attempt another append in this turn.'
    } elseif ([bool]$cadence.due) {
        'ADVISORY ONLY: canonical append readiness is unavailable; continue work, preserve the checkpoint debt, and append after a live/current registration exists.'
    } else {
        'Continue normally; keep intermediate progress locally and append a durable result. Cadence alone does not require a canonical write.'
    }
    return "SEMANTIC CHECKPOINT $disposition`: age_seconds=$($cadence.age_seconds) actions=$($cadence.actions) event_per_turn=false. $instruction"
}

function Test-AppendReady {
    param([Collections.IDictionary]$State)
    return [bool](
        (-not [bool](Get-Value -Object $State -Name 'append_attempted' -Default $false)) -and
        [string](Get-Value -Object $State -Name 'append_outcome' -Default '') -ne 'unknown-outcome' -and
        [string](Get-Value -Object $State -Name 'model_mcp_admission_status' -Default '') -eq 'ready' -and
        [string](Get-Value -Object $State -Name 'write_plane_status' -Default '') -eq 'ready' -and
        (-not [bool](Get-Value -Object $State -Name 'coordination_stop_required' -Default $true)) -and
        [string](Get-Value -Object $State -Name 'turn_memory_status' -Default '') -eq 'open' -and
        [string](Get-Value -Object $State -Name 'turn_memory_lease' -Default '') -eq 'live' -and
        [string](Get-Value -Object $State -Name 'turn_memory_queue' -Default '') -eq 'current' -and
        [string](Get-Value -Object $State -Name 'turn_memory_registration_id' -Default '') -match '^sha256:[a-f0-9]{64}$'
    )
}

function Preserve-TurnMemoryRecoveryHandle {
    param([Collections.IDictionary]$State)
    $handle = Get-Value -Object $State -Name 'turn_memory_unresolved_handle' -Default $null
    if ($null -eq $handle) { return }
    $existing = Get-Value -Object $State -Name 'turn_memory_recovery_handles' -Default $null
    $handles = if ($null -eq $existing) { @() } else { @($existing) }
    $State['turn_memory_recovery_handles'] = @($handles + @($handle) | Select-Object -Last 8)
    [void]$State.Remove('turn_memory_unresolved_handle')
}

function Read-Payload {
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
    try { return ($raw | ConvertFrom-Json -AsHashtable -Depth 32) }
    catch { throw 'invalid_hook_payload' }
}

function Get-SessionId {
    param($Payload)
    foreach ($name in @('session_id', 'thread_id')) {
        $value = [string](Get-Value -Object $Payload -Name $name -Default '')
        if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
    }
    throw 'missing_session_id'
}

function Get-TurnId {
    param($Payload)
    foreach ($name in @('turn_id', 'turnId')) {
        $value = [string](Get-Value -Object $Payload -Name $name -Default '')
        if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
    }
    return ''
}

function Get-Prompt {
    param($Payload)
    foreach ($name in @('prompt', 'user_prompt', 'userPrompt', 'message', 'input')) {
        $value = Get-Value -Object $Payload -Name $name -Default $null
        if ($value -is [string] -and -not [string]::IsNullOrWhiteSpace($value)) {
            if ([Text.Encoding]::UTF8.GetByteCount($value) -gt 262144) { throw 'user_prompt_exceeds_256_kib' }
            return $value
        }
    }
    throw 'missing_user_prompt'
}

function Invoke-TurnEnvelopeHelper {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @(),
        [AllowNull()][string]$InputText = $null
    )
    $helper = Join-Path $PSScriptRoot 'integrity_client_turn_envelope.py'
    if (-not [IO.File]::Exists($helper)) { throw 'turn_envelope_helper_unavailable' }
    $helperItem = Get-Item -LiteralPath $helper -Force
    if (($helperItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'turn_envelope_helper_unsafe' }
    $python = Get-Command python.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $python) {
        $python = Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1
    }
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $python.Source
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $info.StandardInputEncoding = $utf8
    $info.StandardOutputEncoding = $utf8
    $info.StandardErrorEncoding = $utf8
    # Redirected Windows Python otherwise decodes stdin using the ANSI locale,
    # which can turn UTF-8 non-BMP bytes into surrogateescape code points.
    [void]$info.ArgumentList.Add('-X')
    [void]$info.ArgumentList.Add('utf8')
    [void]$info.ArgumentList.Add($helper)
    [void]$info.ArgumentList.Add($Command)
    foreach ($argument in $Arguments) { [void]$info.ArgumentList.Add([string]$argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'turn_envelope_helper_spawn_failed' }
        if ($null -ne $InputText) { $process.StandardInput.Write($InputText) }
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) {
            $process.Kill($true)
            throw 'turn_envelope_helper_timeout'
        }
        $output = $stdout.GetAwaiter().GetResult()
        $errorText = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            if ([string]::IsNullOrWhiteSpace($errorText)) { throw 'turn_envelope_helper_failed' }
            throw $errorText.Trim()
        }
        if ([string]::IsNullOrWhiteSpace($output)) { throw 'turn_envelope_helper_empty_response' }
        return ($output | ConvertFrom-Json -AsHashtable -Depth 16)
    }
    finally { $process.Dispose() }
}

function New-TurnEnvelope {
    param([string]$Prompt, [string]$ThreadId, [string]$TurnId, [long]$Generation)
    return Invoke-TurnEnvelopeHelper -Command 'stage' -Arguments @(
        '--machine-id',(Get-MachineId),'--thread-id',$ThreadId,'--turn-id',$TurnId,
        '--generation',[string]$Generation
    ) -InputText $Prompt
}

function Arm-TurnEnvelope {
    param([string]$TurnRef, [string]$ThreadId, [string]$TurnId, [long]$Generation, [string]$PromptSha256)
    return Invoke-TurnEnvelopeHelper -Command 'arm' -Arguments @(
        '--turn-ref',$TurnRef,'--machine-id',(Get-MachineId),'--thread-id',$ThreadId,
        '--turn-id',$TurnId,'--generation',[string]$Generation,'--prompt-sha256',$PromptSha256
    )
}

function Retire-TurnEnvelope {
    param([string]$TurnRef)
    if ([string]::IsNullOrWhiteSpace($TurnRef)) { return }
    try { [void](Invoke-TurnEnvelopeHelper -Command 'retire' -Arguments @('--turn-ref',$TurnRef,'--preserve-claimed')) }
    catch { }
}

function Get-MachineId {
    $name = [Environment]::MachineName
    if ([string]::IsNullOrWhiteSpace($name)) { throw 'missing_machine_id' }
    $safe = [Text.RegularExpressions.Regex]::Replace($name.ToLowerInvariant(), '[^a-z0-9._-]', '-')
    if ([string]::IsNullOrWhiteSpace($safe)) { throw 'invalid_machine_id' }
    return ('machine:' + $safe)
}

function Get-StateRoot {
    $codexHome = [Environment]::GetEnvironmentVariable('CODEX_HOME')
    if ([string]::IsNullOrWhiteSpace($codexHome)) {
        $profile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
        if ([string]::IsNullOrWhiteSpace($profile)) { throw 'missing_user_profile' }
        $codexHome = Join-Path $profile '.codex'
    }
    $root = [IO.Path]::GetFullPath((Join-Path $codexHome 'integrity-memory\state'))
    if (-not [IO.Directory]::Exists($root)) {
        [void][IO.Directory]::CreateDirectory($root)
    }
    $item = Get-Item -LiteralPath $root -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'unsafe_state_root' }
    return $root
}

function Get-StatePath {
    param([string]$SessionId)
    return (Join-Path (Get-StateRoot) ((Get-Sha256 -Text $SessionId) + '.json'))
}

function Load-State {
    param([string]$SessionId)
    $path = Get-StatePath -SessionId $SessionId
    if (-not [IO.File]::Exists($path)) { return @{} }
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'unsafe_state_file' }
    try { return ([IO.File]::ReadAllText($path, [Text.Encoding]::UTF8) | ConvertFrom-Json -AsHashtable -Depth 32) }
    catch { throw 'invalid_session_state' }
}

function Save-State {
    param([string]$SessionId, [Collections.IDictionary]$State)
    $path = Get-StatePath -SessionId $SessionId
    $State['protocol'] = 'integrity-memory/session-state/v1'
    $State['session_hash'] = Get-Sha256 -Text $SessionId
    $State['updated_utc'] = [DateTimeOffset]::UtcNow.ToString('o')
    $encoded = $State | ConvertTo-Json -Depth 32 -Compress
    $temporary = Join-Path (Split-Path -Parent $path) ('.state-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllText($temporary, $encoded + [Environment]::NewLine, $utf8NoBom)
        Move-Item -LiteralPath $temporary -Destination $path -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Start-RegisteredConnector {
    $codex = Get-Command codex -CommandType Application -ErrorAction Stop | Select-Object -First 1
    # A bounded child also supports Windows codex.cmd shims without shell interpolation.
    $queryInfo = [Diagnostics.ProcessStartInfo]::new()
    $queryInfo.FileName = Join-Path $PSHOME $(if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' })
    $queryInfo.UseShellExecute = $false
    $queryInfo.RedirectStandardOutput = $true
    $queryInfo.RedirectStandardError = $true
    foreach ($arg in @('-NoLogo','-NoProfile','-NonInteractive','-Command',
        ("& '" + $codex.Source.Replace("'", "''") + "' mcp get integrity_client_memory --json; exit `$LASTEXITCODE"))) {
        [void]$queryInfo.ArgumentList.Add($arg)
    }
    $query = [Diagnostics.Process]::new()
    $query.StartInfo = $queryInfo
    $queryTimeout = Get-LifecycleRemainingMilliseconds -Maximum 15000
    try {
        if (-not $query.Start()) { throw 'mcp_registration_unavailable' }
        $output = $query.StandardOutput.ReadToEndAsync()
        $errors = $query.StandardError.ReadToEndAsync()
        if (-not $query.WaitForExit($queryTimeout)) {
            $query.Kill($true)
            [void]$query.WaitForExit(1000)
            throw 'mcp_registration_timeout'
        }
        if ($query.ExitCode -ne 0) { throw 'mcp_registration_unavailable' }
        $entryText = $output.GetAwaiter().GetResult()
    }
    finally { $query.Dispose() }
    $entry = $entryText | ConvertFrom-Json -Depth 16
    $transport = Require-Value -Object $entry -Name 'transport'
    Assert-Equal -Actual (Require-Value -Object $transport -Name 'type') -Expected 'stdio' -Name 'transport_type'

    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = [string](Require-Value -Object $transport -Name 'command')
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $arguments = @(Require-Property -Object $transport -Name 'args')
    foreach ($argument in $arguments) {
        [void]$info.ArgumentList.Add([string]$argument)
    }
    $environment = Get-Value -Object $transport -Name 'env' -Default $null
    if ($null -ne $environment) {
        foreach ($property in $environment.PSObject.Properties) {
            $info.Environment[[string]$property.Name] = [string]$property.Value
        }
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'connector_spawn_failed' }
    return $process
}

function Send-Rpc {
    param([Diagnostics.Process]$Process, [hashtable]$Request)
    $Process.StandardInput.WriteLine(($Request | ConvertTo-Json -Depth 32 -Compress))
    $Process.StandardInput.Flush()
}

function Receive-Rpc {
    param([Diagnostics.Process]$Process, [int]$Id)
    $read = $Process.StandardOutput.ReadLineAsync()
    if (-not $read.Wait((Get-LifecycleRemainingMilliseconds))) { throw 'response_timeout' }
    $line = $read.GetAwaiter().GetResult()
    if ([string]::IsNullOrWhiteSpace($line)) { throw 'response_stream_closed' }
    $response = $line | ConvertFrom-Json -Depth 64
    Assert-Equal -Actual (Require-Value -Object $response -Name 'id') -Expected $Id -Name 'response_id'
    $errorValue = Get-Value -Object $response -Name 'error' -Default $null
    if ($null -ne $errorValue) { throw 'json_rpc_error' }
    return $response
}

function Invoke-Tool {
    param([Diagnostics.Process]$Process, [int]$Id, [string]$Name, [hashtable]$Arguments)
    Send-Rpc -Process $Process -Request @{
        jsonrpc = '2.0'; id = $Id; method = 'tools/call'
        params = @{ name = $Name; arguments = $Arguments }
    }
    $response = Receive-Rpc -Process $Process -Id $Id
    $result = Require-Value -Object $response -Name 'result'
    if ([bool](Get-Value -Object $result -Name 'isError' -Default $false)) {
        $reason = ''
        $code = 'provider_denied'
        try {
            $errorContent = @(Get-Value -Object $result -Name 'content' -Default @())
            $errorDocument = [string]$errorContent[0].text | ConvertFrom-Json -Depth 64
            $errorDocument = Get-Value -Object $errorDocument -Name 'receipt' -Default $errorDocument
            $reason = [string](Get-Value -Object $errorDocument -Name 'reason' -Default '')
            $candidateCode = [string](Get-Value -Object $errorDocument -Name 'reason_code' -Default '')
            if ($candidateCode -cmatch '^[a-z][a-z0-9_]{0,95}$') { $code = $candidateCode }
            if ($reason -ceq 'turn identity collides with another prompt') { $code = 'turn_identity_prompt_collision' }
        } catch { }
        throw ('tool_' + $Name + ':' + $code + ':reason_sha256=' + (Get-Sha256 -Text $reason))
    }
    $content = @(Require-Value -Object $result -Name 'content')
    if ($content.Count -ne 1 -or [string]$content[0].type -ne 'text') { throw 'invalid_tool_content' }
    return ([string]$content[0].text | ConvertFrom-Json -Depth 64)
}

function Open-ConnectorSession {
    $process = Start-RegisteredConnector
    $initialize = $null
    try {
        Send-Rpc -Process $process -Request @{
            jsonrpc = '2.0'; id = 1; method = 'initialize'
            params = @{
                protocolVersion = '2025-06-18'
                capabilities = @{}
                clientInfo = @{ name = 'integrity-memory-hook'; version = $script:HookVersion }
            }
        }
        $initialize = Receive-Rpc -Process $process -Id 1
        $server = Require-Value -Object (Require-Value -Object $initialize -Name 'result') -Name 'serverInfo'
        Assert-Equal -Actual $server.name -Expected 'integrity-client-memory' -Name 'server_name'
        if ([string]$server.version -notin @('1.4.1','1.4.0','2.6.0','2.7.0','2.8.0','2.9.0','2.10.0')) { throw 'mismatch_server_version' }
        Send-Rpc -Process $process -Request @{ jsonrpc = '2.0'; method = 'notifications/initialized'; params = @{} }
        Send-Rpc -Process $process -Request @{ jsonrpc = '2.0'; id = 2; method = 'tools/list'; params = @{} }
        $listed = Receive-Rpc -Process $process -Id 2
        $names = @((Require-Value -Object (Require-Value -Object $listed -Name 'result') -Name 'tools') | ForEach-Object { [string]$_.name })
        $expected = if ([string]$server.version -in @('1.4.1','1.4.0')) {
            $ExpectedTools
        } elseif ([string]$server.version -in @('2.6.0','2.7.0')) {
            $LegacyExpectedTools
        } elseif ([string]$server.version -eq '2.8.0') {
            $PreviousExpectedTools
        } else {
            $DirectCurrentExpectedTools
        }
        Assert-Equal -Actual $names.Count -Expected $expected.Count -Name 'tool_count'
        for ($index = 0; $index -lt $expected.Count; $index++) {
            Assert-Equal -Actual $names[$index] -Expected $expected[$index] -Name ('tool_' + $index)
        }
        return @{ process = $process; initialize = $initialize; tool_names = $names }
    }
    catch {
        try { $process.StandardInput.Close() } catch {}
        if (-not $process.WaitForExit(1000)) { try { $process.Kill($true) } catch {} }
        throw
    }
}

function Close-ConnectorSession {
    param($Session)
    if ($null -eq $Session) { return }
    $process = $Session.process
    try { $process.StandardInput.Close() } catch {}
    if (-not $process.WaitForExit(3000)) { try { $process.Kill($true) } catch {} }
}

function Invoke-TurnMemoryOpen {
    param(
        [string]$MachineId,
        [string]$ThreadId,
        [string]$TurnId,
        [string]$PromptSha256
    )
    $session = $null
    try {
        $session = Open-ConnectorSession
        return Invoke-Tool -Process $session.process -Id 3 -Name 'integrity_turn_memory_open' -Arguments @{
            machine_id = $MachineId
            thread_id = $ThreadId
            turn_id = $TurnId
            prompt_sha256 = $PromptSha256
        }
    }
    finally { Close-ConnectorSession -Session $session }
}

function Invoke-TurnMemoryGap {
    param([string]$RegistrationId, [string]$Stage)
    $session = $null
    try {
        $session = Open-ConnectorSession
        return Invoke-Tool -Process $session.process -Id 3 -Name 'integrity_turn_memory_gap' -Arguments @{
            registration_id = $RegistrationId
            stage = $Stage
        }
    }
    finally { Close-ConnectorSession -Session $session }
}

function Validate-Capabilities {
    param($Capabilities)
    $contractVersion = [string](Require-Value -Object $Capabilities -Name 'contract_version')
    $facade = Require-Value -Object $Capabilities -Name 'facade'
    $serverVersion = [string](Require-Value -Object $facade -Name 'server_version')
    $identity = $contractVersion + '/' + $serverVersion
    if ($identity -notin @('1.5.0/2.6.0','1.6.0/2.7.0','1.7.0/2.8.0','1.8.0/2.9.0','1.9.0/2.10.0')) { throw 'mismatch_contract_identity' }
    if ($identity -ne '1.5.0/2.6.0') {
        $session = Require-Value -Object $facade -Name 'session_admission'
        $presentation = Require-Value -Object $session -Name 'context_presentation'
        Assert-ExactKeys -Object $presentation -Expected @(
            'default_protocol','supported_protocols','legacy_fixed_selector'
        ) -Name 'model_mcp_context_capability_shape'
        Assert-Equal -Actual ([string](Require-Value -Object $presentation -Name 'default_protocol')) -Expected 'integrity-client-memory-mcp/v3/context-admission/v2' -Name 'model_mcp_context_capability_default'
        Assert-Equal -Actual ([string](Require-Value -Object $presentation -Name 'legacy_fixed_selector')) -Expected 'explicit-limit' -Name 'model_mcp_context_capability_legacy'
        $supported = @(Require-Value -Object $presentation -Name 'supported_protocols')
        if (
            $supported.Count -ne 2 -or
            [string]$supported[0] -ne 'integrity-client-memory-mcp/v3/context-admission/v2' -or
            [string]$supported[1] -ne 'integrity-client-memory-mcp/v3/context-admission/v1'
        ) { throw 'model_mcp_context_capability_supported_invalid' }
    }
    Assert-Equal -Actual $Capabilities.facade.session_admission.seed_snapshot_activation -Expected 'lazy-on-first-seed-tool' -Name 'snapshot_activation'
    Assert-Equal -Actual $Capabilities.lifecycle.snapshot_storage -Expected 'private-tmpfs-session-copy' -Name 'snapshot_storage'
    Assert-Equal -Actual ([bool]$Capabilities.lifecycle.startup_seed_copy) -Expected $false -Name 'startup_seed_copy'
    Assert-Equal -Actual $Capabilities.health -Expected 'ready' -Name 'health'
    Assert-Equal -Actual ([bool]$Capabilities.facade.listener) -Expected $false -Name 'listener'
    Assert-Equal -Actual $Capabilities.facade.allowed_consumer -Expected 'client-workstation' -Name 'allowed_consumer'
    Assert-Equal -Actual ([bool]$Capabilities.facade.winops_authorized) -Expected $false -Name 'winops_authorized'
    Assert-FalseMap -Map $Capabilities.authority -Names @('execution','production','route','atlas_planning','uroboros_reuse') -Prefix 'authority'
    if ($identity -eq '1.9.0/2.10.0') {
        Validate-AuthorityContract -Contract (Require-Value -Object $Capabilities -Name 'authority_contract') -ExpectedStatus 'not-evaluated'
    }
    Assert-FalseMap -Map $Capabilities.mutation -Names @('update','delete','import','overwrite','bulk_write') -Prefix 'mutation'
    foreach ($name in @('guardian_ledger','signed_checkpoint','atlas_projection','connectome_compilation','synapse_route_planning','ownership_blast_coordination','deep_mind_graph','concept_recovery','security_harness_admission','uroboros_exact_route_reuse','one_use_authority','passive_outcome_witness','immutable_outcome_feedback','turn_memory_registration','turn_memory_terminal_receipt','turn_memory_coverage_gap')) {
        Assert-Equal -Actual ([bool](Require-Value -Object $Capabilities.processing -Name $name)) -Expected $true -Name ('processing_' + $name)
    }
    Assert-Equal -Actual ([bool]$Capabilities.processing.model_side_route_invention) -Expected $false -Name 'model_side_route_invention'
}

function Invoke-SnapshotAdmission {
    $session = $null
    try {
        $session = Open-ConnectorSession
        $capabilities = Invoke-Tool -Process $session.process -Id 3 -Name 'integrity_memory_capabilities' -Arguments @{}
        Validate-Capabilities -Capabilities $capabilities
        $snapshot = Invoke-Tool -Process $session.process -Id 4 -Name 'integrity_seed_snapshot' -Arguments @{}
        Assert-Equal -Actual ([long]$snapshot.home_record_count) -Expected 0 -Name 'snapshot_home_record_count'
        Assert-Equal -Actual ([bool]$snapshot.production_authority) -Expected $false -Name 'snapshot_production_authority'
        return @{ capabilities = $capabilities; snapshot = $snapshot; tool_names = $session.tool_names }
    }
    finally { Close-ConnectorSession -Session $session }
}

function Validate-FullAdmissionContext {
    param($Context)
    Assert-Equal -Actual ([long](Require-Value -Object $Context -Name 'canonical_writes')) -Expected 0 -Name 'canonical_writes'
    Assert-Equal -Actual ([long](Require-Value -Object $Context -Name 'home_record_count')) -Expected 0 -Name 'home_record_count'
    Assert-Equal -Actual ([bool](Require-Value -Object $Context -Name 'production_authority')) -Expected $false -Name 'production_authority'
    $capabilities = Require-Value -Object $Context -Name 'capabilities'
    Validate-Capabilities -Capabilities $capabilities
    $snapshot = Require-Value -Object $Context -Name 'snapshot'
    Assert-Equal -Actual ([long](Require-Value -Object $snapshot -Name 'home_record_count')) -Expected 0 -Name 'snapshot_home_record_count'
    Assert-Equal -Actual ([bool](Require-Value -Object $snapshot -Name 'production_authority')) -Expected $false -Name 'snapshot_production_authority'
    $cursor = Require-Value -Object $snapshot -Name 'cursor'
    $eventCount = [long](Require-Value -Object $cursor -Name 'event_count')
    $maximumEventId = [long](Require-Value -Object $cursor -Name 'maximum_event_id')
    if ($eventCount -lt 0 -or $maximumEventId -lt 0) { throw 'invalid_snapshot_cursor' }
    $mind = Require-Value -Object $Context -Name 'mind'
    $mindReceipt = Require-Value -Object $mind -Name 'admission_receipt'
    Assert-Equal -Actual ([long](Require-Value -Object $mindReceipt -Name 'home_record_count')) -Expected 0 -Name 'mind_home_record_count'
    Assert-Equal -Actual ([bool](Require-Value -Object $mindReceipt -Name 'production_authority')) -Expected $false -Name 'mind_production_authority'
    Assert-Equal -Actual (Require-Value -Object (Require-Value -Object $mind -Name 'mind') -Name 'memory_source') -Expected 'canonical-seed-action-log' -Name 'mind_source'
    $mindReceiptId = [string](Require-Value -Object $mindReceipt -Name 'receipt_id')
    if ($mindReceiptId -notmatch '^sha256:[a-f0-9]{64}$') { throw 'invalid_mind_receipt_id' }
    $stopRequired = [bool](Require-Value -Object $mindReceipt -Name 'coordination_stop_required')
    $architectureEnvelope = Require-Value -Object $Context -Name 'architecture'
    $architecture = Require-Value -Object $architectureEnvelope -Name 'architecture'
    $summary = Require-Value -Object $architecture -Name 'summary'
    $route = [string](Require-Value -Object $summary -Name 'route_disposition')
    Assert-Equal -Actual $route -Expected ($(if ($stopRequired) { 'stopped' } else { 'ready' })) -Name 'route_disposition'
    $architectureId = [string](Require-Value -Object $architecture -Name 'admission_id')
    if ($architectureId -notmatch '^sha256:[a-f0-9]{64}$') { throw 'invalid_architecture_admission_id' }
    $custody = Require-Value -Object $architectureEnvelope -Name 'custody'
    Assert-Equal -Actual ([long](Require-Value -Object $custody -Name 'home_record_count')) -Expected 0 -Name 'custody_home_record_count'
    Assert-Equal -Actual ([bool](Require-Value -Object $custody -Name 'production_authority')) -Expected $false -Name 'custody_production_authority'
    return @{
        snapshot = $snapshot
        mind_receipt = $mindReceipt
        architecture = $architecture
        event_count = $eventCount
        maximum_event_id = $maximumEventId
        stop_required = $stopRequired
        route_disposition = $route
    }
}

function Validate-ReadPlaneContext {
    param($Context)
    Assert-Equal -Actual ([long](Require-Value -Object $Context -Name 'canonical_writes')) -Expected 0 -Name 'canonical_writes'
    Assert-Equal -Actual ([bool](Require-Value -Object $Context -Name 'production_authority')) -Expected $false -Name 'production_authority'
    $capabilities = Require-Value -Object $Context -Name 'capabilities'
    Validate-Capabilities -Capabilities $capabilities
    $snapshot = Require-Value -Object $Context -Name 'snapshot'
    Assert-Equal -Actual ([long](Require-Value -Object $snapshot -Name 'home_record_count')) -Expected 0 -Name 'snapshot_home_record_count'
    Assert-Equal -Actual ([bool](Require-Value -Object $snapshot -Name 'production_authority')) -Expected $false -Name 'snapshot_production_authority'
    $cursor = Require-Value -Object $snapshot -Name 'cursor'
    $eventCount = [long](Require-Value -Object $cursor -Name 'event_count')
    $maximumEventId = [long](Require-Value -Object $cursor -Name 'maximum_event_id')
    if ($eventCount -lt 0 -or $maximumEventId -lt 0) { throw 'invalid_snapshot_cursor' }
    $mind = Require-Value -Object $Context -Name 'mind'
    $mindReceipt = Require-Value -Object $mind -Name 'admission_receipt'
    Assert-Equal -Actual ([long](Require-Value -Object $mindReceipt -Name 'home_record_count')) -Expected 0 -Name 'mind_home_record_count'
    Assert-Equal -Actual ([bool](Require-Value -Object $mindReceipt -Name 'production_authority')) -Expected $false -Name 'mind_production_authority'
    $mindReceiptId = [string](Require-Value -Object $mindReceipt -Name 'receipt_id')
    if ($mindReceiptId -notmatch '^sha256:[a-f0-9]{64}$') { throw 'invalid_mind_receipt_id' }
    $stopRequired = [bool](Get-Value -Object $mindReceipt -Name 'coordination_stop_required' -Default $true)

    $architectureEnvelope = Get-Value -Object $Context -Name 'architecture' -Default @{}
    $architecture = Get-Value -Object $architectureEnvelope -Name 'architecture' -Default $null
    $architectureReady = $false
    $route = $(if ($stopRequired) { 'stopped' } else { 'ready' })
    if ($null -ne $architecture) {
        $summary = Require-Value -Object $architecture -Name 'summary'
        $architectureId = [string](Require-Value -Object $architecture -Name 'admission_id')
        if ($architectureId -notmatch '^sha256:[a-f0-9]{64}$') { throw 'invalid_architecture_admission_id' }
        $route = [string](Require-Value -Object $summary -Name 'route_disposition')
        Assert-Equal -Actual $route -Expected ($(if ($stopRequired) { 'stopped' } else { 'ready' })) -Name 'route_disposition'
        $architectureReady = $true
    }
    else {
        Assert-Equal -Actual ([bool](Get-Value -Object $architectureEnvelope -Name 'production_authority' -Default $false)) -Expected $false -Name 'architecture_production_authority'
        Assert-Equal -Actual ([long](Get-Value -Object $architectureEnvelope -Name 'canonical_writes' -Default 0)) -Expected 0 -Name 'architecture_canonical_writes'
    }
    return @{
        snapshot = $snapshot
        mind_receipt = $mindReceipt
        architecture = $architecture
        architecture_ready = $architectureReady
        event_count = $eventCount
        maximum_event_id = $maximumEventId
        stop_required = $stopRequired
        route_disposition = $route
    }
}

function Invoke-FullAdmission {
    param([string]$Intent)
    $session = $null
    try {
        $session = Open-ConnectorSession
        $context = Invoke-Tool -Process $session.process -Id 3 -Name 'integrity_context_admission' -Arguments @{ intent = $Intent }
        $expectedProtocol = Get-NegotiatedContextProtocol -Context $context -RequestedProtocol 'integrity-client-memory-mcp/v3/context-admission/v2'
        [void](Validate-ContextPresentation -Context $context -ExpectedProtocol $expectedProtocol)
        [void](Validate-ReadPlaneContext -Context $context)
        return @{ context = $context; tool_names = $session.tool_names }
    }
    finally { Close-ConnectorSession -Session $session }
}

function Write-AdditionalContext {
    param([string]$HookEvent, [string]$Context)
    $output = @{
        continue = $true
        hookSpecificOutput = @{ hookEventName = $HookEvent; additionalContext = $Context }
    }
    [Console]::Out.WriteLine(($output | ConvertTo-Json -Compress -Depth 8))
}

function Deny-Hook {
    param([string]$Reason)
    [Console]::Error.WriteLine(('Integrity admission blocked this lifecycle step: ' + $Reason))
    exit 2
}

function Tool-EnvelopeText {
    param($Payload)
    $input = Get-Value -Object $Payload -Name 'tool_input' -Default @{}
    return ($input | ConvertTo-Json -Depth 32 -Compress)
}

function Get-ToolInput {
    param($Payload)
    $input = Get-Value -Object $Payload -Name 'tool_input' -Default @{}
    if ($input -is [string]) {
        try { return ($input | ConvertFrom-Json -AsHashtable -Depth 32) }
        catch { throw 'invalid_tool_input' }
    }
    return $input
}

function Is-DestructiveActionLogAttempt {
    param($Payload)
    $text = Tool-EnvelopeText -Payload $Payload
    if ($text -match '(?is)\bdelete\s+from\s+.{0,64}\bevents\b') { return $true }
    if (
        $text -match '(?i)(?:127\.0\.0\.1|localhost):8765/api/events' -and
        $text -match '(?i)(?:-X|--request|-Method)\s*DELETE'
    ) { return $true }
    if (
        $text -match '(?i)/var/lib/codex-action-log/(?:codex-action-log\.sqlite3|integrity-seed-dirty)' -and
        $text -match '(?i)\b(?:rm|unlink|mv|cp|install|truncate|dd|shred|sqlite3)\b'
    ) { return $true }
    return $false
}

function Is-MeaningfulMutation {
    param($Payload)
    $name = [string](Get-Value -Object $Payload -Name 'tool_name' -Default '')
    if ($name -match '(?i)(?:apply_patch|\bEdit\b|\bWrite\b|NotebookEdit|integrity_append_event)') { return $true }
    $text = Tool-EnvelopeText -Payload $Payload
    return [bool]($text -match '(?i)\b(?:apply_patch|rm|mv|cp|install|chmod|chown|setfacl|git\s+(?:commit|push)|systemctl\s+(?:start|stop|restart|enable|disable)|sed\s+-i|tee)\b')
}

function Is-AppendTool {
    param($Payload)
    $name = [string](Get-Value -Object $Payload -Name 'tool_name' -Default '')
    return $name -match '(?i)integrity_append_event$'
}

function Validate-AppendToolInput {
    param($Payload)
    $inputValue = Get-ToolInput -Payload $Payload
    if ($inputValue -isnot [Collections.IDictionary]) { throw 'append arguments must be an object' }
    $allowed = @('event_uid','kind','summary','details','tags','authority_decision','context_admission_id')
    foreach ($key in $inputValue.Keys) {
        if ([string]$key -notin $allowed) { throw 'append arguments contain unknown fields' }
    }
    # The canonical MCP verifies equality with its current admitted context.
    $contextId = Get-Value -Object $inputValue -Name 'context_admission_id' -Default $null
    if ($contextId -isnot [string] -or $contextId -cnotmatch '\Asha256:[a-f0-9]{64}\z') {
        throw 'context_admission_id must be a sha256 digest'
    }
    $eventUid = Get-Value -Object $inputValue -Name 'event_uid' -Default $null
    if ($eventUid -isnot [string] -or $eventUid -notmatch '^client:[A-Za-z0-9][A-Za-z0-9._:-]{7,154}$') {
        throw 'event_uid must match the bounded immutable client: identity'
    }
    $kind = Get-Value -Object $inputValue -Name 'kind' -Default $null
    if ($kind -isnot [string] -or $kind -notin @('concept','task','thought')) {
        throw 'kind must be one of: concept, task, thought'
    }
    $summary = Get-Value -Object $inputValue -Name 'summary' -Default $null
    if ($summary -isnot [string] -or [string]::IsNullOrWhiteSpace($summary) -or $summary.Length -gt 2000) {
        throw 'summary must contain 1 to 2000 characters'
    }
    $details = Get-Value -Object $inputValue -Name 'details' -Default @{}
    if ($details -isnot [Collections.IDictionary]) { throw 'details must be an object' }
    $tags = @()
    if ($inputValue.Contains('tags')) { $tags = $inputValue['tags'] }
    if (
        $tags -is [string] -or
        $tags -is [Collections.IDictionary] -or
        $tags -isnot [Collections.IEnumerable]
    ) {
        throw 'tags must be a bounded string array'
    }
    $tagList = @($tags)
    if ($tagList.Count -gt 20) { throw 'tags must be a bounded string array' }
    foreach ($tag in $tagList) {
        if ($tag -isnot [string] -or [string]::IsNullOrWhiteSpace($tag) -or $tag.Trim().Length -gt 80) {
            throw 'tags must be a bounded string array'
        }
    }
    if ($inputValue.Contains('authority_decision')) {
        $authority = Get-Value -Object $inputValue -Name 'authority_decision' -Default $null
        if ($authority -isnot [Collections.IDictionary]) {
            throw 'authority_decision must be an object'
        }
    }
}

function Is-ContextAdmissionTool {
    param($Payload)
    $name = [string](Get-Value -Object $Payload -Name 'tool_name' -Default '')
    return $name -match '(?i)integrity_context_admission(?:_current_turn)?$'
}

function Is-CurrentContextAdmissionTool {
    param($Payload)
    $name = [string](Get-Value -Object $Payload -Name 'tool_name' -Default '')
    return $name -match '(?i)integrity_context_admission_current_turn$'
}

function Is-IntegrityMemoryTool {
    param($Payload)
    $name = [string](Get-Value -Object $Payload -Name 'tool_name' -Default '')
    return $name -match '(?i)(?:^|__)integrity_[a-z0-9_]+$'
}

function Is-SubstantiveAction {
    param($Payload)
    $name = [string](Get-Value -Object $Payload -Name 'tool_name' -Default '')
    return -not [string]::IsNullOrWhiteSpace($name) -and $name -notmatch '(?i)(?:^|__)integrity_[a-z0-9_]+$' -and $name -notmatch '(?i)(?:^|__|codex_app)set_thread_title$'
}

function Find-ContextAdmission {
    param($Value)
    $queue = [Collections.Queue]::new()
    $queue.Enqueue($Value)
    $visited = 0
    while ($queue.Count -gt 0 -and $visited -lt 256) {
        $visited++
        $current = $queue.Dequeue()
        if ($null -eq $current) { continue }
        if ($current -is [string]) {
            if ($current.Length -gt 1048576) { continue }
            try { $queue.Enqueue(($current | ConvertFrom-Json -AsHashtable -Depth 64)) }
            catch {}
            continue
        }
        $protocol = [string](Get-Value -Object $current -Name 'protocol' -Default '')
        if (
            $protocol -match '/context-admission/v(?:1|2)$' -and
            $null -ne (Get-Value -Object $current -Name 'capabilities' -Default $null) -and
            $null -ne (Get-Value -Object $current -Name 'snapshot' -Default $null) -and
            $null -ne (Get-Value -Object $current -Name 'mind' -Default $null) -and
            $null -ne (Get-Value -Object $current -Name 'architecture' -Default $null)
        ) { return $current }
        if ($current -is [Collections.IDictionary]) {
            foreach ($nested in $current.Values) { $queue.Enqueue($nested) }
            continue
        }
        if ($current -is [Collections.IEnumerable]) {
            foreach ($nested in $current) { $queue.Enqueue($nested) }
            continue
        }
        foreach ($property in $current.PSObject.Properties) { $queue.Enqueue($property.Value) }
    }
    return $null
}

function Find-RetryableWalDenial {
    param($Value)
    $queue = [Collections.Queue]::new()
    $queue.Enqueue($Value)
    $visited = 0
    while ($queue.Count -gt 0 -and $visited -lt 256) {
        $visited++
        $current = $queue.Dequeue()
        if ($null -eq $current) { continue }
        if ($current -is [string]) {
            if ($current.Length -gt 1048576) { continue }
            try { $queue.Enqueue(($current | ConvertFrom-Json -AsHashtable -Depth 64)) }
            catch {}
            continue
        }
        if (
            [string](Get-Value -Object $current -Name 'reason_code' -Default '') -eq 'seed_catalog_checkpoint_required' -and
            [bool](Get-Value -Object $current -Name 'automatic_retry_allowed' -Default $false) -and
            [long](Get-Value -Object $current -Name 'canonical_writes' -Default -1) -eq 0 -and
            [string](Get-Value -Object $current -Name 'retry_disposition' -Default '') -eq 'exact-envelope-after-supported-read-seal'
        ) { return $current }
        if ($current -is [Collections.IDictionary]) {
            foreach ($nested in $current.Values) { $queue.Enqueue($nested) }
            continue
        }
        if ($current -is [Collections.IEnumerable]) {
            foreach ($nested in $current) { $queue.Enqueue($nested) }
            continue
        }
        foreach ($property in $current.PSObject.Properties) { $queue.Enqueue($property.Value) }
    }
    return $null
}

function Find-RetryableTransportDenial {
    param($Value)
    $queue = [Collections.Queue]::new()
    $queue.Enqueue($Value)
    $visited = 0
    while ($queue.Count -gt 0 -and $visited -lt 256) {
        $visited++
        $current = $queue.Dequeue()
        if ($null -eq $current) { continue }
        if ($current -is [string]) {
            if ($current.Length -gt 1048576) { continue }
            try { $queue.Enqueue(($current | ConvertFrom-Json -AsHashtable -Depth 64)) }
            catch {}
            continue
        }
        if (
            [string](Get-Value -Object $current -Name 'protocol' -Default '') -eq 'integrity-client/turn-broker-denial/v1' -and
            [string](Get-Value -Object $current -Name 'failure_layer' -Default '') -eq 'broker-upstream' -and
            -not [bool](Get-Value -Object $current -Name 'request_sent' -Default $true) -and
            [bool](Get-Value -Object $current -Name 'automatic_retry_allowed' -Default $false) -and
            [long](Get-Value -Object $current -Name 'canonical_writes' -Default -1) -eq 0 -and
            [string](Get-Value -Object $current -Name 'retry_disposition' -Default '') -eq 'exact-envelope-after-pre-send-transport'
        ) { return $current }
        if ($current -is [Collections.IDictionary]) {
            foreach ($nested in $current.Values) { $queue.Enqueue($nested) }
            continue
        }
        if ($current -is [Collections.IEnumerable]) {
            foreach ($nested in $current) { $queue.Enqueue($nested) }
            continue
        }
        foreach ($property in $current.PSObject.Properties) { $queue.Enqueue($property.Value) }
    }
    return $null
}

function Find-AppendReceipt {
    param($Value)
    $queue = [Collections.Queue]::new()
    $queue.Enqueue($Value)
    $visited = 0
    while ($queue.Count -gt 0 -and $visited -lt 128) {
        $visited++
        $current = $queue.Dequeue()
        if ($null -eq $current) { continue }
        if ($current -is [string]) {
            if ($current.Length -gt 1048576) { continue }
            try { $queue.Enqueue(($current | ConvertFrom-Json -AsHashtable -Depth 64)) }
            catch {}
            continue
        }
        $outcome = [string](Get-Value -Object $current -Name 'outcome' -Default '')
        $eventId = Get-Value -Object $current -Name 'event_id' -Default $null
        if ($null -eq $eventId) { $eventId = Get-Value -Object $current -Name 'id' -Default $null }
        $numericEventId = 0L
        if (
            $outcome -match '^(?i:created|duplicate)$' -and
            [long]::TryParse([string]$eventId, [ref]$numericEventId) -and
            $numericEventId -gt 0
        ) {
            return $current
        }
        if ($current -is [Collections.IDictionary]) {
            foreach ($nested in $current.Values) { $queue.Enqueue($nested) }
            continue
        }
        if ($current -is [Collections.IEnumerable]) {
            foreach ($nested in $current) { $queue.Enqueue($nested) }
            continue
        }
        foreach ($property in $current.PSObject.Properties) { $queue.Enqueue($property.Value) }
    }
    return $null
}

function Validate-AppendReceipt {
    param($Receipt)
    $outcome = [string](Require-Value -Object $Receipt -Name 'outcome')
    if ($outcome -notin @('created', 'duplicate')) { throw 'invalid_append_outcome' }
    $eventId = 0L
    if (-not [long]::TryParse([string](Require-Value -Object $Receipt -Name 'event_id'), [ref]$eventId) -or $eventId -le 0) {
        throw 'invalid_append_event_id'
    }
    Assert-Equal -Actual ([string](Require-Value -Object $Receipt -Name 'action_outcome')) -Expected 'confirmed-success' -Name 'append_action_outcome'
    Assert-Equal -Actual ([bool](Require-Value -Object $Receipt -Name 'automatic_retry_allowed')) -Expected $false -Name 'append_automatic_retry'
    Assert-Equal -Actual ([bool](Require-Value -Object $Receipt -Name 'production_authority')) -Expected $false -Name 'append_production_authority'
    Assert-Equal -Actual ([long](Require-Value -Object $Receipt -Name 'home_record_count')) -Expected 0 -Name 'append_home_record_count'
    if ($null -eq (Require-Value -Object $Receipt -Name 'passive_witness')) { throw 'missing_append_passive_witness' }
    $requestSent = [bool](Require-Value -Object $Receipt -Name 'request_sent')
    $grantConsumed = [bool](Require-Value -Object $Receipt -Name 'grant_consumed')
    $feedbackReceiptId = ''
    if ($outcome -eq 'created') {
        Assert-Equal -Actual $requestSent -Expected $true -Name 'append_request_sent'
        Assert-Equal -Actual $grantConsumed -Expected $true -Name 'append_grant_consumed'
        if ($null -eq (Require-Value -Object $Receipt -Name 'one_use_authority')) { throw 'missing_append_one_use_authority' }
        $feedbackReceiptId = [string](Require-Value -Object $Receipt -Name 'feedback_receipt_id')
        if ([string]::IsNullOrWhiteSpace($feedbackReceiptId)) { throw 'missing_append_feedback_receipt' }
    }
    else {
        Assert-Equal -Actual $requestSent -Expected $false -Name 'duplicate_request_sent'
        Assert-Equal -Actual $grantConsumed -Expected $false -Name 'duplicate_grant_consumed'
    }
    return @{
        outcome = $outcome
        event_id = $eventId
        canonical_writes = $(if ($outcome -eq 'created') { 1 } else { 0 })
        request_sent = $requestSent
        grant_consumed = $grantConsumed
        feedback_receipt_id = $feedbackReceiptId
    }
}

function Validate-ModelMcpAdmission {
    param([Collections.IDictionary]$State)
    if ([string](Get-Value -Object $State -Name 'model_mcp_admission_status' -Default '') -ne 'ready') {
        throw 'model_mcp_context_admission_required'
    }
    if ([bool](Get-Value -Object $State -Name 'model_mcp_production_authority' -Default $true)) {
        throw 'model_mcp_authority_boundary_invalid'
    }
    if ([long](Get-Value -Object $State -Name 'model_mcp_home_record_count' -Default -1) -ne 0) {
        throw 'model_mcp_home_boundary_invalid'
    }
    if (
        [string](Get-Value -Object $State -Name 'turn_memory_status' -Default '') -ne 'open' -or
        [string](Get-Value -Object $State -Name 'turn_memory_lease' -Default '') -ne 'live' -or
        [string](Get-Value -Object $State -Name 'turn_memory_queue' -Default '') -ne 'current' -or
        [string](Get-Value -Object $State -Name 'turn_memory_registration_id' -Default '') -notmatch '^sha256:[a-f0-9]{64}$'
    ) { throw 'turn_memory_registration_required' }
}

function Validate-CurrentAdmission {
    param($Payload, [Collections.IDictionary]$State)
    if ([string](Get-Value -Object $State -Name 'admission_status' -Default '') -ne 'ready') { throw 'full_admission_missing' }
    $turn = Get-TurnId -Payload $Payload
    $admittedTurn = [string](Get-Value -Object $State -Name 'turn_id' -Default '')
    if (-not [string]::IsNullOrWhiteSpace($admittedTurn) -and $turn -ne $admittedTurn) { throw 'turn_admission_mismatch' }
    if ([bool](Get-Value -Object $State -Name 'production_authority' -Default $true)) { throw 'authority_boundary_invalid' }
    if ([long](Get-Value -Object $State -Name 'home_record_count' -Default -1) -ne 0) { throw 'home_boundary_invalid' }
}

$payload = Read-Payload
$sessionId = Get-SessionId -Payload $payload
$turnId = Get-TurnId -Payload $payload

if ($Event -eq 'SessionStart') {
    try {
        Write-AdditionalContext -HookEvent $Event -Context (
            "INTEGRITY client SESSION PENDING INTENT ADMISSION`n" +
            "MEMORY AUTHORITY: provider=memory-only; target_action=not-evaluated; provider boundary is not a target denial. " +
            "Home=0. No Seed snapshot or shared admission state was opened at process startup. " +
            "For the first substantive step, the model must call integrity_context_admission exactly once with the current intent."
        )
    }
    catch {
        Write-AdditionalContext -HookEvent $Event -Context ('INTEGRITY client SESSION BLOCKED: ' + $_.Exception.Message + '. No continuity or authority claim is valid.')
    }
    exit 0
}

# Serialize read/modify/write across hook processes for this session. The MCP
# request itself runs outside this lock. Python's Windows hook uses the same name.
$stateLockKey = Get-Sha256 -Text ([IO.Path]::GetFullPath((Get-StatePath -SessionId $sessionId)).ToLowerInvariant())
$stateMutex = [Threading.Mutex]::new($false, ('Local\IntegrityClientState-' + $stateLockKey))
$stateLocked = $false
try {
try { $stateLocked = $stateMutex.WaitOne(10000) }
catch [Threading.AbandonedMutexException] { $stateLocked = $true }
if (-not $stateLocked) { throw 'session_state_lock_timeout' }

if ($Event -in @('UserPromptSubmit', 'SubagentStart')) {
    try {
        $intent = if ($Event -eq 'UserPromptSubmit') { Get-Prompt -Payload $payload } else { 'Initialize this fresh subagent with current canonical project coordination and safety context.' }
        if ([string]::IsNullOrWhiteSpace($turnId)) { $turnId = 'turn:' + [Guid]::NewGuid().ToString('D') }
        $state = Load-State -SessionId $sessionId
        $priorGeneration = Get-Value -Object $state -Name 'turn_memory_generation' -Default 0L
        if (
            $priorGeneration -is [bool] -or
            ($priorGeneration -isnot [int] -and $priorGeneration -isnot [long]) -or
            [long]$priorGeneration -lt 0
        ) {
            $priorGeneration = 0L
        }
        $priorTurnRef = [string](Get-Value -Object $state -Name 'turn_ref' -Default '')
        if (-not [string]::IsNullOrWhiteSpace($priorTurnRef)) { Retire-TurnEnvelope -TurnRef $priorTurnRef }
        $nextGeneration = [long]$priorGeneration + 1L
        $envelope = New-TurnEnvelope -Prompt $intent -ThreadId $sessionId -TurnId $turnId -Generation $nextGeneration
        $state['admission_status'] = 'provisional'
        $state['turn_id'] = $turnId
        # Keep transport identity for envelope/trace; registration identifies the owner intent.
        $state['turn_memory_intent_id'] = 'intent:' + ([string]$envelope.turn_ref_digest).Substring(7)
        $state['prompt_sha256'] = Get-Sha256 -Text $intent
        $state['prompt_bytes'] = [long](Require-Value -Object $envelope -Name 'prompt_bytes')
        $state['prompt_segment_count'] = [long](Require-Value -Object $envelope -Name 'segment_count')
        $state['prompt_coverage'] = [string](Require-Value -Object $envelope -Name 'prompt_coverage')
        $state['prompt_truncation'] = $false
        $state['turn_ref'] = [string](Require-Value -Object $envelope -Name 'turn_ref')
        $state['turn_ref_digest'] = [string](Require-Value -Object $envelope -Name 'turn_ref_digest')
        $state['turn_ref_expires_utc'] = [string](Require-Value -Object $envelope -Name 'expires_utc')
        $state['coordination_stop_required'] = $false
        $state['route_disposition'] = 'pending'
        $state['write_plane_status'] = 'pending'
        $state['home_record_count'] = 0
        $state['production_authority'] = $false
        $state['model_mcp_admission_status'] = 'required'
        $state['model_mcp_admission_attempted'] = $false
        $state['model_mcp_read_seal_retry_count'] = 0L
        $state['model_mcp_transport_retry_count'] = 0L
        $state['model_mcp_home_record_count'] = 0
        $state['model_mcp_production_authority'] = $false
        $state['turn_memory_generation'] = $nextGeneration
        $state['turn_memory_status'] = 'provisional'
        $state['turn_memory_lease'] = 'provisional'
        $state['turn_memory_queue'] = 'current'
        $state['turn_memory_lease_updated_utc'] = [DateTimeOffset]::UtcNow.ToString('o')
        [void]$state.Remove('model_mcp_expected_context_protocol')
        [void]$state.Remove('model_mcp_selection_receipt_id')
        [void]$state.Remove('retry_disposition')
        Preserve-TurnMemoryRecoveryHandle -State $state
        foreach ($name in @('turn_memory_registration_id','turn_memory_namespace_fingerprint','turn_memory_opened_utc','turn_memory_terminal_receipt_id','turn_memory_gap_receipt_id','turn_memory_failure')) {
            [void]$state.Remove($name)
        }
        foreach ($name in @('snapshot_id','event_count','maximum_event_id','mind_receipt_id','concept_recovery_digest','coordination_digest','architecture_admission_id','atlas_projection_digest','connectome_compilation_id','synapse_plan_id','model_mcp_snapshot_id','model_mcp_mind_receipt_id','model_mcp_architecture_admission_id')) {
            [void]$state.Remove($name)
        }
        if ([string](Get-Value -Object $state -Name 'append_outcome' -Default '') -ne 'unknown-outcome') {
            $state['append_outcome'] = 'not-started'
            $state['append_attempted'] = $false
            $state['automatic_retry_allowed'] = $true
            [void]$state.Remove('append_event_id')
            [void]$state.Remove('append_feedback_receipt_id')
        }
        Save-State -SessionId $sessionId -State $state

        $contextText = @(
            'INTEGRITY client READ PLANE PENDING v3',
            'No hook-owned Seed admission/snapshot process was opened. No canonical Turn Memory registration was opened.',
            ("Invoke integrity_context_admission_current_turn exactly once in the model-owned MCP session with turn_ref='" + $state['turn_ref'] + "'; omit limit for adaptive selection. Do not repeat or reconstruct the prompt in tool arguments. Use its immutable snapshot for later Seed reads."),
            'A closed architecture, witness, Security Harness, coordination or append gate is write/action-plane state only. Continue read-only from the returned canonical snapshot.',
            'If the user asks to edit, delete or erase a canonical event, explicitly refuse that mutation and state that the only permitted historical correction is a new append-only corrective event. Do not append it unless the user separately and explicitly requests creation.',
            'MEMORY AUTHORITY: provider=memory-only; target_action=not-evaluated; provider boundary is not a target denial. coordination scope=integrity-memory-route; Seed append and external targets are unaffected.',
            'Home=0 canonical_writes=0',
            "TURN MEMORY PROVISIONAL generation=$($state['turn_memory_generation']) lease=provisional queue=current. A canonical registration is created only after the context admission receipt validates.",
            (Get-SemanticContext -State $state)
        ) -join "`n"
        Write-AdditionalContext -HookEvent $Event -Context $contextText
        exit 0
    }
    catch {
        Write-AdditionalContext -HookEvent $Event -Context ('INTEGRITY client READ PLANE PENDING: local hook state unavailable: ' + $_.Exception.Message + '. The model must still call canonical integrity_context_admission exactly once.')
        exit 0
    }
}

$state = Load-State -SessionId $sessionId

if ($Event -eq 'PreToolUse') {
    if (Is-DestructiveActionLogAttempt -Payload $payload) {
        Deny-Hook -Reason 'canonical Action Log events are immutable; append a corrective event instead'
    }
    if ([string](Get-Value -Object $state -Name 'append_outcome' -Default '') -eq 'unknown-outcome' -and (Is-AppendTool -Payload $payload)) {
        Deny-Hook -Reason 'prior append outcome is unknown; automatic retry is forbidden and event_uid reconciliation is required'
    }
    $retryDisposition = [string](Get-Value -Object $state -Name 'retry_disposition' -Default '')
    $retryPending = $retryDisposition -in @(
        'exact-envelope-after-supported-read-seal',
        'exact-envelope-after-pre-send-transport'
    )
    if ($retryPending -and (Is-IntegrityMemoryTool -Payload $payload) -and -not (Is-CurrentContextAdmissionTool -Payload $payload)) {
        Deny-Hook -Reason 'only the identical current-turn admission is allowed while retry is pending'
    }
    if (Is-ContextAdmissionTool -Payload $payload) {
        if ([bool](Get-Value -Object $state -Name 'model_mcp_admission_attempted' -Default $false)) {
            Deny-Hook -Reason 'model MCP context admission is single-shot for the current turn'
        }
        try {
            $toolInput = Get-ToolInput -Payload $payload
            if (Is-CurrentContextAdmissionTool -Payload $payload) {
                $turnRef = [string](Require-Value -Object $toolInput -Name 'turn_ref')
                Assert-Equal -Actual $turnRef -Expected ([string]$state['turn_ref']) -Name 'model_mcp_turn_ref'
                [void](Arm-TurnEnvelope -TurnRef $turnRef -ThreadId $sessionId -TurnId ([string]$state['turn_id']) -Generation ([long]$state['turn_memory_generation']) -PromptSha256 ([string]$state['prompt_sha256']))
                if ($retryPending) {
                    [void]$state.Remove('retry_disposition')
                }
            }
            else {
                $modelIntent = [string](Require-Value -Object $toolInput -Name 'intent')
                if ([string]::IsNullOrWhiteSpace($modelIntent)) { throw 'empty_model_mcp_intent' }
                Assert-Equal -Actual (Get-Sha256 -Text $modelIntent) -Expected ([string]$state['prompt_sha256']) -Name 'model_mcp_intent'
            }
            $state['model_mcp_admission_attempted'] = $true
            $state['model_mcp_admission_status'] = 'pending'
            $state['model_mcp_expected_context_protocol'] = $(if (Test-Property -Object $toolInput -Name 'limit') { 'integrity-client-memory-mcp/v3/context-admission/v1' } else { 'integrity-client-memory-mcp/v3/context-admission/v2' })
            Save-State -SessionId $sessionId -State $state
        }
        catch { Deny-Hook -Reason $_.Exception.Message }
        exit 0
    }
    if ((Is-IntegrityMemoryTool -Payload $payload) -and -not (Is-AppendTool -Payload $payload)) {
        exit 0
    }
    if (Is-AppendTool -Payload $payload) {
        try { Validate-AppendToolInput -Payload $payload }
        catch { Deny-Hook -Reason $_.Exception.Message }
        try { Validate-ModelMcpAdmission -State $state }
        catch { Deny-Hook -Reason $_.Exception.Message }
        if ([bool](Get-Value -Object $state -Name 'append_attempted' -Default $false)) {
            Deny-Hook -Reason 'only one append attempt is allowed in the current turn'
        }
        $state['append_attempted'] = $true
        $state['append_outcome'] = 'started'
        $state['unresolved_mutation'] = $true
        $state['automatic_retry_allowed'] = $false
        Save-State -SessionId $sessionId -State $state
    }
    # Cadence preserves local progress, not an obligatory early canonical write.
    # The admission, one-attempt and unknown-outcome guards above are unchanged.
    exit 0
}

if ($Event -eq 'PostToolUse') {
    if (Is-ContextAdmissionTool -Payload $payload) {
        $completedInput = Get-ToolInput -Payload $payload
        $completedRef = [string](Get-Value -Object $completedInput -Name 'turn_ref' -Default '')
        $completedIntent = [string](Get-Value -Object $completedInput -Name 'intent' -Default '')
        $superseded = if (Is-CurrentContextAdmissionTool -Payload $payload) {
            -not [string]::IsNullOrWhiteSpace($completedRef) -and
            $completedRef -ne [string](Get-Value -Object $state -Name 'turn_ref' -Default '')
        } else {
            -not [string]::IsNullOrWhiteSpace($completedIntent) -and
            (Get-Sha256 -Text $completedIntent) -ne [string](Get-Value -Object $state -Name 'prompt_sha256' -Default '')
        }
        if ($superseded) {
            Write-AdditionalContext -HookEvent $Event -Context 'INTEGRITY SUPERSEDED ADMISSION: late response belongs to an earlier intent; current admission state is unchanged. Do not bind that receipt to the current intent.'
            exit 0
        }
        try {
            if (-not [bool](Get-Value -Object $state -Name 'model_mcp_admission_attempted' -Default $false)) {
                throw 'model_mcp_context_admission_not_started'
            }
            $response = Get-Value -Object $payload -Name 'tool_response' -Default @{}
            $context = Find-ContextAdmission -Value $response
            $retryableWal = Find-RetryableWalDenial -Value $response
            $retryableTransport = Find-RetryableTransportDenial -Value $response
            if (
                $null -eq $context -and
                (Is-CurrentContextAdmissionTool -Payload $payload) -and
                $null -ne $retryableWal -and
                [long](Get-Value -Object $state -Name 'model_mcp_read_seal_retry_count' -Default 0L) -lt 1L
            ) {
                $state['model_mcp_read_seal_retry_count'] = 1L
                $state['model_mcp_admission_attempted'] = $false
                $state['model_mcp_admission_status'] = 'required'
                $state['automatic_retry_allowed'] = $true
                $state['retry_disposition'] = 'exact-envelope-after-supported-read-seal'
                Save-State -SessionId $sessionId -State $state
                Write-AdditionalContext -HookEvent $Event -Context 'INTEGRITY READ PLANE RETRYABLE: the exact current turn_ref was not consumed. After the Seed owner completes the supported read-seal recovery, retry integrity_context_admission_current_turn once with the identical turn_ref. No other tool is admitted before that retry.'
                exit 0
            }
            if (
                $null -eq $context -and
                (Is-CurrentContextAdmissionTool -Payload $payload) -and
                $null -ne $retryableTransport -and
                [long](Get-Value -Object $state -Name 'model_mcp_transport_retry_count' -Default 0L) -lt 1L
            ) {
                [void](Arm-TurnEnvelope -TurnRef ([string]$state['turn_ref']) -ThreadId $sessionId -TurnId ([string]$state['turn_id']) -Generation ([long]$state['turn_memory_generation']) -PromptSha256 ([string]$state['prompt_sha256']))
                $state['model_mcp_transport_retry_count'] = 1L
                $state['model_mcp_admission_attempted'] = $false
                $state['model_mcp_admission_status'] = 'required'
                $state['automatic_retry_allowed'] = $true
                $state['retry_disposition'] = 'exact-envelope-after-pre-send-transport'
                Save-State -SessionId $sessionId -State $state
                Write-AdditionalContext -HookEvent $Event -Context 'INTEGRITY TRANSPORT RETRYABLE: no admission request bytes were sent and the exact current turn_ref remains armed. Retry integrity_context_admission_current_turn once with the identical turn_ref. No other Integrity tool is admitted before that retry.'
                exit 0
            }
            if ($null -eq $context) { throw 'model_mcp_context_receipt_missing' }
            $requestedProtocol = [string](Require-Value -Object $state -Name 'model_mcp_expected_context_protocol')
            $expectedProtocol = Get-NegotiatedContextProtocol -Context $context -RequestedProtocol $requestedProtocol
            $selection = Validate-ContextPresentation -Context $context -ExpectedProtocol $expectedProtocol
            if (Is-CurrentContextAdmissionTool -Payload $payload) {
                $binding = Require-Value -Object $context -Name 'prompt_binding'
                Assert-Equal -Actual ([string](Require-Value -Object $binding -Name 'turn_ref_digest')) -Expected ([string]$state['turn_ref_digest']) -Name 'model_mcp_turn_ref_digest'
                Assert-Equal -Actual ([string](Require-Value -Object $binding -Name 'prompt_sha256')) -Expected ([string]$state['prompt_sha256']) -Name 'model_mcp_full_prompt_sha256'
                Assert-Equal -Actual ([long](Require-Value -Object $binding -Name 'prompt_bytes')) -Expected ([long]$state['prompt_bytes']) -Name 'model_mcp_full_prompt_bytes'
                Assert-Equal -Actual ([long](Require-Value -Object $binding -Name 'segment_count')) -Expected ([long]$state['prompt_segment_count']) -Name 'model_mcp_prompt_segment_count'
                Assert-Equal -Actual ([string](Require-Value -Object $binding -Name 'prompt_coverage')) -Expected 'text-only' -Name 'model_mcp_prompt_coverage'
                Assert-Equal -Actual ([bool](Require-Value -Object $binding -Name 'truncation')) -Expected $false -Name 'model_mcp_prompt_truncation'
            }
            $validated = Validate-ReadPlaneContext -Context $context
        }
        catch {
            foreach ($name in @('turn_memory_registration_id','turn_memory_namespace_fingerprint','turn_memory_opened_utc','turn_memory_terminal_receipt_id','turn_memory_gap_receipt_id')) {
                [void]$state.Remove($name)
            }
            $state['admission_status'] = 'detached'
            $state['model_mcp_admission_status'] = 'invalid'
            $state['turn_memory_status'] = 'detached'
            $state['turn_memory_lease'] = 'expired'
            $state['turn_memory_queue'] = 'recovery'
            $state['turn_memory_lease_updated_utc'] = [DateTimeOffset]::UtcNow.ToString('o')
            $state['turn_memory_failure'] = $_.Exception.Message
            $state['coordination_stop_required'] = $false
            $state['route_disposition'] = 'detached'
            $state['write_plane_status'] = 'unavailable'
            Save-State -SessionId $sessionId -State $state
            Write-AdditionalContext -HookEvent $Event -Context ('INTEGRITY READ PLANE RECEIPT INVALID: ' + $_.Exception.Message + '. TURN MEMORY DETACHED lease=expired queue=recovery; no validated canonical registration is bound to this intent. Report this canonical MCP infrastructure fault explicitly; do not reconstruct memory from local files.')
            exit 0
        }

        $state['admission_status'] = 'ready'
        $state['model_mcp_admission_status'] = 'ready'
        $state['model_mcp_snapshot_id'] = [string]$validated.snapshot.snapshot_id
        $state['model_mcp_mind_receipt_id'] = [string]$validated.mind_receipt.receipt_id
        if ([bool]$validated.architecture_ready) {
            $state['model_mcp_architecture_admission_id'] = [string]$validated.architecture.admission_id
            $state['architecture_admission_id'] = [string]$validated.architecture.admission_id
            $state['write_plane_status'] = 'ready'
        }
        else {
            [void]$state.Remove('model_mcp_architecture_admission_id')
            [void]$state.Remove('architecture_admission_id')
            $state['write_plane_status'] = 'unavailable'
        }
        $state['model_mcp_home_record_count'] = 0
        $state['model_mcp_production_authority'] = $false
        $state['model_mcp_negotiated_context_protocol'] = $expectedProtocol
        if ($null -ne $selection) {
            $state['model_mcp_selection_receipt_id'] = [string](Require-Value -Object $selection -Name 'receipt_id')
        }
        $state['event_count'] = [long]$validated.event_count
        $state['maximum_event_id'] = [long]$validated.maximum_event_id
        $state['mind_receipt_id'] = [string]$validated.mind_receipt.receipt_id
        $state['coordination_stop_required'] = [bool]$validated.stop_required
        $state['route_disposition'] = [string]$validated.route_disposition
        [void]$state.Remove('retry_disposition')

        $turnMemoryContext = ''
        try {
            $openArguments = @{
                machine_id = Get-MachineId
                thread_id = $sessionId
                turn_id = [string](Get-Value -Object $state -Name 'turn_memory_intent_id' -Default $state['turn_id'])
                prompt_sha256 = [string]$state['prompt_sha256']
                generation = [long]$state['turn_memory_generation']
            }
            $state['turn_memory_unresolved_handle'] = $openArguments
            try {
                $registrationResult = Invoke-TurnMemoryOpen -MachineId $openArguments.machine_id -ThreadId $openArguments.thread_id -TurnId $openArguments.turn_id -PromptSha256 $openArguments.prompt_sha256
            }
            catch {
                if ($_.Exception.Message -notin @('response_timeout','response_stream_closed')) { throw }
                [void](Get-LifecycleRemainingMilliseconds -Maximum 1000)
                $registrationResult = Invoke-TurnMemoryOpen -MachineId $openArguments.machine_id -ThreadId $openArguments.thread_id -TurnId $openArguments.turn_id -PromptSha256 $openArguments.prompt_sha256
            }
            $registration = Require-Value -Object $registrationResult -Name 'receipt'
            Assert-Equal -Actual ([bool](Require-Property -Object $registration -Name 'terminal_required')) -Expected $true -Name 'turn_terminal_required'
            Assert-Equal -Actual ([bool](Require-Property -Object $registration -Name 'production_authority')) -Expected $false -Name 'turn_production_authority'
            Assert-Equal -Actual ([string](Require-Value -Object $registration -Name 'prompt_sha256')) -Expected ([string]$state['prompt_sha256']) -Name 'turn_prompt_sha256'
            $registeredIdentity = Require-Value -Object $registration -Name 'identity'
            foreach ($field in @('machine_id','thread_id','turn_id')) {
                Assert-Equal -Actual ([string](Require-Value -Object $registeredIdentity -Name $field)) -Expected ([string]$openArguments[$field]) -Name ('turn_identity_' + $field)
            }
            $registrationId = [string](Require-Value -Object $registration -Name 'receipt_id')
            $namespaceFingerprint = [string](Require-Value -Object $registration -Name 'namespace_fingerprint')
            if ($registrationId -notmatch '^sha256:[a-f0-9]{64}$' -or $namespaceFingerprint -notmatch '^sha256:[a-f0-9]{64}$') {
                throw 'turn_registration_invalid'
            }
            $state['turn_memory_status'] = 'open'
            $state['turn_memory_lease'] = 'live'
            $state['turn_memory_queue'] = 'current'
            $state['turn_memory_registration_id'] = $registrationId
            $state['turn_memory_namespace_fingerprint'] = $namespaceFingerprint
            $state['turn_memory_opened_utc'] = [DateTimeOffset]::UtcNow.ToString('o')
            $state['turn_memory_lease_updated_utc'] = [DateTimeOffset]::UtcNow.ToString('o')
            [void]$state.Remove('turn_memory_unresolved_handle')
            [void]$state.Remove('turn_memory_failure')
            $turnMemoryContext = "TURN MEMORY LIVE registration_id=$registrationId generation=$($state['turn_memory_generation']) lease=live queue=current."
        }
        catch {
            Preserve-TurnMemoryRecoveryHandle -State $state
            foreach ($name in @('turn_memory_registration_id','turn_memory_namespace_fingerprint','turn_memory_opened_utc','turn_memory_terminal_receipt_id','turn_memory_gap_receipt_id')) {
                [void]$state.Remove($name)
            }
            $state['turn_memory_status'] = 'registration-unavailable'
            $state['turn_memory_lease'] = 'expired'
            $state['turn_memory_queue'] = 'recovery'
            $state['turn_memory_lease_updated_utc'] = [DateTimeOffset]::UtcNow.ToString('o')
            $state['turn_memory_failure'] = $_.Exception.Message
            $turnMemoryContext = 'TURN MEMORY REGISTRATION UNAVAILABLE (OUTCOME UNRESOLVED): ' + $_.Exception.Message + '. The canonical read plane remains ready; the exact open identity is retained in bounded recovery, no validated registration id is bound, and append remains gated.'
        }
        Save-State -SessionId $sessionId -State $state
        Write-AdditionalContext -HookEvent $Event -Context (
            "INTEGRITY CANONICAL READ PLANE READY: snapshot=$($state['model_mcp_snapshot_id']) " +
            "cursor=$($state['event_count'])/$($state['maximum_event_id']) mind=$($state['model_mcp_mind_receipt_id']) " +
            "route=$($state['route_disposition']) write_plane=$($state['write_plane_status']) " +
            "Home=0 canonical_writes=0. MEMORY AUTHORITY: provider=memory-only; target_action=not-evaluated; provider boundary is not a target denial; coordination scope=integrity-memory-route; Seed append and external targets are unaffected. Continue Seed reads in this same MCP session even when its write_plane is unavailable. $turnMemoryContext"
        )
        exit 0
    }
    if (Is-AppendTool -Payload $payload) {
        try { Validate-ModelMcpAdmission -State $state }
        catch { Deny-Hook -Reason $_.Exception.Message }
        if (-not [bool](Get-Value -Object $state -Name 'append_attempted' -Default $false)) {
            Deny-Hook -Reason 'append PostToolUse arrived without a gated PreToolUse attempt'
        }
        $response = Get-Value -Object $payload -Name 'tool_response' -Default @{}
        $receipt = Find-AppendReceipt -Value $response
        try {
            if ($null -eq $receipt) { throw 'append_receipt_missing' }
            $verifiedReceipt = Validate-AppendReceipt -Receipt $receipt
            $state['append_outcome'] = [string]$verifiedReceipt.outcome
            $state['append_event_id'] = [long]$verifiedReceipt.event_id
            $state['append_canonical_writes'] = [long]$verifiedReceipt.canonical_writes
            $state['append_feedback_receipt_id'] = [string]$verifiedReceipt.feedback_receipt_id
            $state['unresolved_mutation'] = $false
            $state['automatic_retry_allowed'] = $false
            Close-SemanticCheckpoint -State $state -EventId ([long]$verifiedReceipt.event_id)
        }
        catch {
            $state['append_outcome'] = 'unknown-outcome'
            $state['unresolved_mutation'] = $true
            $state['automatic_retry_allowed'] = $false
        }
    }
    elseif (Is-SubstantiveAction -Payload $payload) {
        $tool = [string](Get-Value -Object $payload -Name 'tool_name' -Default '')
        $mutation = Is-MeaningfulMutation -Payload $payload
        if ($mutation) {
            $state['unresolved_mutation'] = $true
            $state['last_mutation_tool'] = $tool
        }
        $semanticCadence = Start-SemanticProgress -State $state -Tool $tool -Mutation $mutation
        $semanticNotice = Test-NewSemanticNotice -State $state
    }
    else { exit 0 }
    Save-State -SessionId $sessionId -State $state
    if (Is-AppendTool -Payload $payload) {
        if ([string]$state['append_outcome'] -eq 'created') {
            Write-AdditionalContext -HookEvent $Event -Context (
                "INTEGRITY APPEND PASSIVE WITNESS: outcome=created " +
                "event_id=$($state['append_event_id']) canonical_writes=1 automatic_retry_allowed=false " +
                "feedback=$($state['append_feedback_receipt_id']). " +
                "Report this verified numeric event id. End the final answer exactly: Событие создано №$($state['append_event_id'])."
            )
        }
        elseif ([string]$state['append_outcome'] -eq 'duplicate') {
            Write-AdditionalContext -HookEvent $Event -Context (
                "INTEGRITY APPEND PASSIVE WITNESS: outcome=duplicate " +
                "event_id=$($state['append_event_id']) canonical_writes=0 automatic_retry_allowed=false. " +
                "Do not claim a new write. End the final answer exactly: Событие уже существовало №$($state['append_event_id'])."
            )
        }
        else {
            Write-AdditionalContext -HookEvent $Event -Context (
                'INTEGRITY APPEND UNKNOWN-OUTCOME: the request may have started; automatic retry is forbidden. ' +
                'Do not claim success or stop until immutable event_uid reconciliation.'
            )
        }
    }
    elseif ($semanticNotice) {
        Write-AdditionalContext -HookEvent $Event -Context (Get-SemanticContext -State $state)
    }
    exit 0
}

if ($Event -in @('Stop', 'SubagentStop')) {
    Retire-TurnEnvelope -TurnRef ([string](Get-Value -Object $state -Name 'turn_ref' -Default ''))
    $turnMemoryContext = ''
    $registrationId = [string](Get-Value -Object $state -Name 'turn_memory_registration_id' -Default '')
    if (-not [string]::IsNullOrWhiteSpace($registrationId)) {
        try {
            $coverage = Invoke-TurnMemoryGap -RegistrationId $registrationId -Stage 'stop'
            $terminal = Get-Value -Object $coverage -Name 'terminal_receipt' -Default $null
            if ($null -ne $terminal) {
                $outcome = [string](Require-Value -Object $terminal -Name 'outcome')
                $receiptId = [string](Require-Value -Object $terminal -Name 'receipt_id')
                $state['turn_memory_status'] = 'closed'
                $state['turn_memory_queue'] = 'archive'
                $state['turn_memory_terminal_receipt_id'] = $receiptId
                $turnMemoryContext = "TURN MEMORY TERMINAL RECEIPT VERIFIED: outcome=$outcome receipt_id=$receiptId. End with the corresponding Seed event number(s), or 'Seed — no new event' for no-event."
            }
            elseif ([bool](Get-Value -Object $coverage -Name 'gap_recorded' -Default $false)) {
                $gap = Require-Value -Object $coverage -Name 'receipt'
                $state['turn_memory_status'] = 'coverage-debt'
                $state['turn_memory_queue'] = 'recovery'
                $state['turn_memory_gap_receipt_id'] = [string](Require-Value -Object $gap -Name 'receipt_id')
                $turnMemoryContext = "TURN MEMORY COVERAGE GAP RECORDED: terminal receipt is missing; gap_receipt_id=$($gap.receipt_id). Do not claim no-event."
            }
            $state['turn_memory_lease'] = 'expired'
            $state['turn_memory_lease_updated_utc'] = [DateTimeOffset]::UtcNow.ToString('o')
        }
        catch {
            $state['turn_memory_status'] = 'coverage-unobservable'
            $state['turn_memory_lease'] = 'expired'
            $state['turn_memory_queue'] = 'recovery'
            $state['turn_memory_lease_updated_utc'] = [DateTimeOffset]::UtcNow.ToString('o')
            $state['turn_memory_failure'] = $_.Exception.Message
            $turnMemoryContext = 'TURN MEMORY COVERAGE UNOBSERVABLE: ' + $_.Exception.Message + '. Do not claim this turn is covered.'
        }
    }
    elseif ([string](Get-Value -Object $state -Name 'turn_memory_status' -Default '') -eq 'provisional') {
        $state['turn_memory_lease'] = 'expired'
        $state['turn_memory_lease_updated_utc'] = [DateTimeOffset]::UtcNow.ToString('o')
        if ([bool](Get-Value -Object $state -Name 'model_mcp_admission_attempted' -Default $false)) {
            $state['turn_memory_status'] = 'detached'
            $state['turn_memory_queue'] = 'recovery'
            $turnMemoryContext = 'TURN MEMORY ADMISSION DETACHED: the attempted context admission never produced a validated receipt; no canonical registration exists and this local generation is queued for recovery, not coverage debt.'
        }
        else {
            $state['turn_memory_status'] = 'expired-provisional'
            $state['turn_memory_queue'] = 'archive'
            $turnMemoryContext = 'TURN MEMORY PROVISIONAL EXPIRED: context admission was never attempted, so no canonical registration or coverage debt exists; the local generation is archived.'
        }
    }
    elseif ([string](Get-Value -Object $state -Name 'turn_memory_status' -Default '') -eq 'detached') {
        $state['turn_memory_lease'] = 'expired'
        $state['turn_memory_queue'] = 'recovery'
        $state['turn_memory_lease_updated_utc'] = [DateTimeOffset]::UtcNow.ToString('o')
        $turnMemoryContext = 'TURN MEMORY DETACHED: no validated canonical registration exists; the local generation remains in recovery and is not coverage debt.'
    }
    elseif ([string](Get-Value -Object $state -Name 'turn_memory_status' -Default '') -in @('registration-unavailable','registration-unresolved')) {
        $state['turn_memory_lease'] = 'expired'
        $state['turn_memory_queue'] = 'recovery'
        $state['turn_memory_lease_updated_utc'] = [DateTimeOffset]::UtcNow.ToString('o')
        $turnMemoryContext = 'TURN MEMORY REGISTRATION UNAVAILABLE: the canonical read plane was admitted, but no validated registration id is bound; recovery is required and no coverage gap can be recorded locally.'
    }
    else {
        $turnMemoryContext = 'TURN MEMORY COVERAGE UNOBSERVABLE: this turn has no canonical registration id. Do not claim it is covered.'
    }
    if ($state.Count -gt 0) { Save-State -SessionId $sessionId -State $state }
    $semanticContext = ''
    if ([bool](Get-SemanticCadence -State $state).open) {
        $semanticContext = "`n" + (Get-SemanticContext -State $state)
    }
    if ([string](Get-Value -Object $state -Name 'append_outcome' -Default '') -eq 'unknown-outcome') {
        Write-AdditionalContext -HookEvent $Event -Context ($turnMemoryContext + "`nINTEGRITY APPEND UNKNOWN-OUTCOME: do not retry; reconcile the immutable event_uid before claiming a write." + $semanticContext)
        exit 0
    }
    if ([bool](Get-Value -Object $state -Name 'unresolved_mutation' -Default $false)) {
        Write-AdditionalContext -HookEvent $Event -Context ($turnMemoryContext + "`nINTEGRITY ACTION-PLANE WARNING: a meaningful mutation lacks verified append-only closure. This warning does not block read-only memory or ending the chat." + $semanticContext)
        exit 0
    }
    if (-not [string]::IsNullOrWhiteSpace($turnMemoryContext)) {
        Write-AdditionalContext -HookEvent $Event -Context ($turnMemoryContext + $semanticContext)
    }
    exit 0
}

exit 0
}
finally {
    if ($stateLocked) { $stateMutex.ReleaseMutex() }
    $stateMutex.Dispose()
}
