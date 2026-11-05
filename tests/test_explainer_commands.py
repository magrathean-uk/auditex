"""R4: executable pre blocks survive rendering with PowerShell syntax intact."""
from copy import deepcopy
import gzip
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from azure_tenant_audit.explainer import build_view, render, render_full
from azure_tenant_audit.explainer.generate import _units, _chunk, LIMITS
from azure_tenant_audit.explainer.textkit import expand_template

ROOT = Path(__file__).resolve().parents[1]
B, C, T = [json.loads((ROOT / 'configs' / f'explainer-{name}.json').read_text())
           for name in ('baselines', 'what-to-collect', 'template')]
T = expand_template(T)


def test_all_policy_cells_compact_and_full_keep_source_commands(tmp_path):
    """Visit every cell/form; parse each distinct emitted command and its raw source.

    Navigation in pre blocks remains portal prose, with ordinary word limits.
    PowerShell's parser is read-only: no command is ever invoked.
    """
    cases, seen_policies = {}, set()
    for cell in T['cells']:
        pid = cell['policy_id']
        order = T['policies'][pid]['sections']
        pair = cell['reason_pairs'][0]
        cites = cell.get('cited_variants', [cell['cited']])[0]
        if cell['cell'] == 'section_not_collected':
            cites = [s for s in order if s in pair['reason_text']]
        rec = dict(policy_id=pid, cell=cell['cell'], verdict=cell['verdict'], **pair, cited_sections=cites)
        view = build_view(rec, {s: [] for s in order}, order, baselines=B, collection=C)
        for render_fn, key in ((render, 'remediation_steps'), (render_full, 'remediation_steps_full')):
            out = render_fn(rec, view, templates=T)
            for text, step in zip(out['remediation_steps'], cell[key], strict=True):
                if not step.get('command'):
                    assert len(text.split()) <= 30
                    continue
                assert len(step['source']) == 1 and not step['forced_piece']
                assert step['units'] == [text]
                source = step['source'][0]
                unit = next(u for u in B['policies'][source['policy_id']]['instructions']
                            if u['source'] == source and u.get('command'))
                assert text == unit['text']  # no prose transformation or join
                assert not re.search(r'-(?:and|or)\s*;', text, re.I)
                assert not any(line.rstrip().endswith('`') for line in text.splitlines())
                raw = gzip.decompress((ROOT / 'tests/fixtures/explainer/baselines/raw' / (source['file'] + '.gz')).read_bytes()).decode().splitlines()
                raw = raw[source['line_start'] - 1:source['line_end']]
                raw = '\n'.join(line for line in raw if not line.strip().startswith('```'))
                raw = re.sub(r'</?(?:pre|b|i|u|em|strong|code|br)\s*/?>', '', raw)
                raw = raw.replace('\u2013', '-').replace('\u2014', '-')
                cases[text] = {'source': raw, 'shown': text}
                seen_policies.add(pid)
    assert seen_policies == {pid for pid, pol in T['policies'].items() if pol['command_units']}
    assert len(cases) == 6
    aad = next(text for text in cases if '$NonCompliantDomains' in text)
    assert '\n$NonCompliantDomains =' in aad
    assert '\n# Remediate each non-compliant domain\nInvoke-MgGraphRequest' in aad
    assert '\n# Verify domain configurations\n$AllDomains =' in aad
    pwsh = shutil.which('pwsh')
    if pwsh is None:
        pytest.skip('PowerShell parser unavailable; source identity controls above still ran')
    path = tmp_path / 'commands.json'
    path.write_text(json.dumps(list(cases.values())))
    script = r'''
$ErrorActionPreference = 'Stop'
$rows = Get-Content -LiteralPath $args[0] -Raw | ConvertFrom-Json
foreach ($row in $rows) {
    $shapes = @()
    foreach ($text in @($row.source, $row.shown)) {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
        if ($errors.Count) { throw ($errors | ConvertTo-Json -Depth 4) }
        # Include every AST node and command name; line comments cannot swallow
        # assignments/commands without changing this complete syntax-tree shape.
        $shapes += ,@($ast.FindAll({param($node) $true}, $true) | ForEach-Object {
            if ($_ -is [System.Management.Automation.Language.CommandAst]) {
                'Command:' + $_.GetCommandName()
            } else { $_.GetType().Name }
        })
    }
    if (($shapes[0] -join '|') -cne ($shapes[1] -join '|')) { throw 'AST changed during rendering' }
}
Write-Output $rows.Count
'''
    ps = tmp_path / 'parse.ps1'
    ps.write_text(script)
    result = subprocess.run([pwsh, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(ps), str(path)],
                            capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr
    assert int(result.stdout.strip()) == len(cases)


def test_only_whole_executable_units_are_exempt_from_word_limit():
    import sys
    sys.path.insert(0, str(ROOT / 'tests'))
    from explainer_checks.corpus import base_pairs as local_pairs
    from explainer_checks.support import local_resources
    from explainer_checks.context import Context
    from explainer_checks.chk_s import Output, check_s
    from explainer_checks.chk_e import check_e
    from explainer_checks.chk_e3 import check_e3
    command = "Get-Thing -Name '" + ' '.join(['word'] * 40) + "'"
    row = {'text': command, 'kind': 'pre', 'command': True, 'source': {'policy_id': 'p', 'file': 'p.md', 'line_start': 1, 'line_end': 4}}
    units, _, _ = _units([row], False)
    assert _chunk(units)[0]['text'] == command
    assert len(_chunk(units)) == 1 and len(command.split()) > 30
    assert 'exempt from step_words only' in LIMITS['command_units']
    pair = deepcopy(next(p for p in local_pairs() if p['prompt']['record']['verdict'] == 'not_met'))
    res = deepcopy(local_resources())
    pid = pair['prompt']['record']['policy_id']
    res.pol_meta[pid]['command_units'] = [command]
    pair['prompt']['data']['approved_remediation'] = [command]
    ctx = Context(pair, res)
    out = Output(obj={'explanation': 'The requirement differs from the baseline.', 'remediation_steps': [command], 'evidence_refs': ['e0']})
    for check in (check_s, check_e, check_e3):
        assert check(ctx, out)['pass'], check(ctx, out)
    assert not check_s(ctx, Output(obj=dict(out.obj, remediation_steps=[command] * 7)))['pass']
    from azure_tenant_audit.explainer.render import _validate_output
    _validate_output(out.obj, 'not_met', command_units=[command])
    with pytest.raises(ValueError, match='remediation exceeds limits'):
        _validate_output(out.obj, 'not_met')
    for variant in (command + '  ', command.replace('-', '\u2013')):
        benign = Output(obj=dict(out.obj, remediation_steps=[variant]))
        assert check_e(ctx, benign)['pass'] and check_e3(ctx, benign)['pass']
    multiline = command + " # comment\nGet-Other"
    res.pol_meta[pid]['command_units'] = [multiline]
    pair['prompt']['data']['approved_remediation'] = [multiline]
    multiline_ctx = Context(pair, res)
    assert multiline_ctx.whole_command(multiline)
    assert not multiline_ctx.whole_command(multiline.replace('\n', ' '))
    fragment = Output(obj=dict(out.obj, remediation_steps=[command[:command.rfind(' word')]]))
    assert not check_e3(ctx, fragment)['pass']
    prose = 'Review ' + ' '.join(['settings'] * 40) + '.'
    assert not check_s(ctx, Output(obj=dict(out.obj, remediation_steps=[prose])))['pass']
    row.update(text=prose, kind='para', command=False)
    pieces, _, _ = _units([row], False)
    assert len(pieces) > 1 and all(len(p['text'].split()) <= 30 for p in pieces)
