"""Self-contained decision review/editor; no browser storage or external requests."""
import html
import json

import decisions


def markup(programs, states, scan_as_of):
    rows = []
    for program in programs:
        key = program["key"]
        rows.append(
            f'<div class="workflow-review-row"><b>{html.escape(program["title"])}</b>'
            f'<p data-review-status="{key}">Snapshot workflow — review details</p>'
            f'<button class="workflow-btn" data-edit-decision="{key}">Review snapshot</button></div>')
    seed = json.dumps({"programs": programs, "states": states, "scan_as_of": scan_as_of},
                      ensure_ascii=True).replace("<", "\\u003c").replace("&", "\\u0026")
    options = "".join(f'<option>{html.escape(status)}</option>'
                      for status in sorted(decisions.STATUSES))
    return ("""
<section class="card workflow-review" aria-labelledby="workflow-review-title">
 <h3 id="workflow-review-title">Review all three programs</h3>
 <p class="workflow-snapshot">Scan evidence is immutable. Workflow status is a governance
 record, not proof of remediation. Owner and approver are self-reported under shared
 function-key access, not verified identities.</p>
 <p id="workflow-mode" class="workflow-message" role="status" aria-live="polite">
 Read-only snapshot. Live workflow is available only on the deployed /api/assessment page.</p>
 <div class="workflow-auth" id="workflow-auth" hidden>
  <label for="workflow-key">Function key (held in memory only)</label>
  <input id="workflow-key" type="password" autocomplete="off" spellcheck="false">
  <button class="workflow-btn" id="workflow-connect" type="button">Load current workflow</button>
 </div>
 <div class="workflow-actions"><button class="workflow-btn" id="workflow-refresh" hidden>
 Refresh workflow</button></div>
 %s
</section>
<dialog id="workflow-dialog" class="workflow-dialog" aria-labelledby="workflow-title"
 aria-describedby="workflow-help">
 <h2 id="workflow-title" tabindex="-1">Review decision</h2>
 <p id="workflow-help" class="workflow-snapshot">Owner and approved by are self-reported.
 Verified does not establish that controls passed. No tenant configuration is changed.</p>
 <p id="workflow-evidence" class="workflow-snapshot"></p>
 <p id="workflow-form-message" class="workflow-message" role="status" aria-live="polite"></p>
 <form id="workflow-form">
  <fieldset class="workflow-fields" id="workflow-fields" disabled>
   <legend>Governance record</legend>
   <label for="decision-owner">Accountable owner (self-reported)</label>
   <input id="decision-owner" name="owner" autocomplete="off">
   <label for="decision-status">Status</label>
   <select id="decision-status" name="status">%s</select>
   <label for="decision-due">Due date</label>
   <input id="decision-due" name="due_date" placeholder="YYYY-MM-DD or ISO timestamp"
    aria-describedby="decision-date-help">
   <small id="decision-date-help">Dates are inclusive through the UTC day.
    Timestamps use their exact instant; include an offset (for example +03:00).</small>
   <label for="decision-notes">Notes / supporting evidence</label>
   <textarea id="decision-notes" name="notes"></textarea>
   <div id="decision-compensation">
    <label for="decision-control">Compensating control</label>
    <textarea id="decision-control" name="compensating_control"></textarea>
   </div>
   <div id="decision-acceptance">
    <label for="decision-rationale">Acceptance rationale</label>
    <textarea id="decision-rationale" name="rationale"></textarea>
    <label for="decision-approver">Approved by (self-reported, not authenticated identity)</label>
    <input id="decision-approver" name="approved_by" autocomplete="off">
    <label for="decision-expiry">Acceptance expiry</label>
    <input id="decision-expiry" name="expires_at" placeholder="YYYY-MM-DD or ISO timestamp"
     aria-describedby="decision-date-help">
   </div>
  </fieldset>
  <div class="workflow-actions">
   <button class="workflow-btn primary" id="workflow-save" type="submit" disabled>Save decision</button>
   <button class="workflow-btn" id="workflow-reload" type="button" hidden>Reload and discard draft</button>
   <button class="workflow-btn" id="workflow-close" type="button">Close</button>
  </div>
 </form>
 <h3>Recorded change history</h3>
 <p class="workflow-snapshot">Field changes, not an authenticated identity audit trail.</p>
 <ol id="workflow-history" class="workflow-history"></ol>
</dialog>
<script type="application/json" id="workflow-seed">%s</script>
""" % ("".join(rows), options, seed)).strip()


JS = r"""
(() => {
  'use strict';
  const find = id => document.getElementById(id);
  const seed = JSON.parse(find('workflow-seed').textContent);
  const programs = seed.programs;
  let states = seed.states, current = false, saving = false, loading = false;
  let editorKey = null, editorRevision = null, editorOpener = null, key = '';
  let editorInstance = 0;
  const dialog = find('workflow-dialog'), form = find('workflow-form');
  const marker = document.querySelector('meta[name="decision-context"]');
  const host = location.hostname.toLowerCase();
  const live = marker && marker.content === 'live' && location.protocol === 'https:' &&
    location.pathname.replace(/\/$/, '') === '/api/assessment' &&
    !/^(localhost|127(?:\.\d+){3}|\[::1\])$/.test(host);
  const message = (id, text, error = false) => {
    const node = find(id); node.textContent = text;
    node.classList.toggle('error', error);
  };
  const text = (tag, value, cls) => {
    const node = document.createElement(tag); node.textContent = value;
    if (cls) node.className = cls; return node;
  };
  function derived(program, state) {
    const conflict = state.status === 'Verified' && program.failed_controls > 0;
    const active = program.failed_controls > 0 || (state.persisted &&
      (state.data_error || state.overdue || state.acceptance_expired ||
       !['Verified', 'False positive'].includes(state.status)));
    return {...state, active, evidence_conflict: conflict,
      display_status: state.data_error ? 'Workflow data invalid' : conflict ?
        'Verification needs review' : state.acceptance_expired ?
        'Risk acceptance expired' : state.status};
  }
  function render(asOf) {
    const counts = {overdue:0, expiring:0, expired:0, unassigned:0, conflicting:0};
    programs.forEach(program => {
      const state = derived(program, states[program.key]);
      if (state.active) {
        counts.overdue += Number(Boolean(state.overdue));
        counts.expiring += Number(Boolean(state.acceptance_expiring));
        counts.expired += Number(Boolean(state.acceptance_expired));
        counts.unassigned += Number(typeof state.owner !== 'string' || !state.owner.trim());
        counts.conflicting += Number(state.evidence_conflict);
      }
      const label = !state.persisted && !program.failed_controls ?
        'No recorded decision; no failed controls in this scan' : state.display_status;
      document.querySelector('[data-review-status="'+program.key+'"]').textContent =
        (current ? 'Current workflow: ' : 'Snapshot workflow: ') + label +
        (state.active ? ' · Requires review' : '');
      document.querySelectorAll('[data-workflow="'+program.key+'"]').forEach(node => {
        node.replaceChildren();
        node.append(text('span', state.display_status,
          'dstatus ' + (state.evidence_conflict || state.acceptance_expired ? 'expired' :
                        state.overdue ? 'overdue' : '')));
        node.append(text('p', 'Owner (self-reported): '+(state.owner || 'Unassigned')+
          ' · Due: '+(state.due_date || 'Not assigned'), 'workflow-snapshot'));
        if (state.evidence_conflict) node.append(text('p',
          'Evidence conflict: manually Verified, but '+program.failed_controls+
          ' control(s) failed in the immutable scan. Review verification.', 'workflow-message error'));
        if (state.acceptance) node.append(text('p', 'Risk acceptance: '+
          state.acceptance.rationale+' · Approved by (self-reported): '+
          state.acceptance.approved_by+' · expires '+state.acceptance.expires_at, 'acceptance'));
        if (state.compensating_control) node.append(text('p',
          'Compensating control: '+state.compensating_control, 'acceptance'));
        if (state.notes) node.append(text('p', 'Notes: '+state.notes, 'acceptance'));
        if (state.data_error) node.append(text('p', 'Workflow data invalid: '+
          state.data_error, 'workflow-message error'));
      });
    });
    find('decision-attention').textContent = [
      counts.overdue+' overdue', counts.expiring+' acceptances expiring within 7 days',
      counts.expired+' expired', counts.unassigned+' unassigned', counts.conflicting+' evidence conflicts'
    ].join(' · ') + ' — ' + (current ? 'workflow as of '+asOf : 'snapshot as of '+seed.scan_as_of);
    document.querySelectorAll('[data-edit-decision]').forEach(button => {
      button.textContent = current ? 'Review / edit decision' : 'Review snapshot';
    });
  }
  function setUnavailable(reason) {
    current = false; states = seed.states;
    render(seed.scan_as_of);
    find('decision-attention').textContent =
      'Current workflow attention unavailable. Snapshot values are not current.';
    message('workflow-mode', reason+' Scan evidence is unchanged; displayed workflow is not current.', true);
    find('workflow-save').disabled = true;
  }
  async function request(method, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch('/api/decisions', {
        method, cache:'no-store', credentials:'same-origin', redirect:'error',
        referrerPolicy:'no-referrer', signal:controller.signal,
        headers:{'x-functions-key':key, ...(body ? {'Content-Type':'application/json'} : {})},
        ...(body ? {body:JSON.stringify(body)} : {})
      });
      let payload;
      try { payload = await response.json(); } catch (_) { throw new Error('Invalid workflow API response.'); }
      if (!response.ok) {
        const error = new Error(payload.error || 'Workflow request failed ('+response.status+').');
        error.status = response.status; throw error;
      }
      return payload;
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('Request timed out; server outcome is unknown. Reload before retrying.');
      throw error;
    } finally { clearTimeout(timer); }
  }
  async function refresh() {
    if (!live || !key || loading) throw new Error('Load current workflow with a function key first.');
    loading = true;
    find('workflow-refresh').disabled = true;
    try {
      const payload = await request('GET');
      if (payload.store_status !== 'ok' || !payload.as_of ||
          !programs.every(p => payload.decisions && payload.decisions[p.key] &&
            typeof payload.decisions[p.key].revision === 'string' &&
            typeof payload.decisions[p.key].persisted === 'boolean' &&
            !payload.decisions[p.key].data_error)) throw new Error('Current workflow is unavailable or invalid.');
      states = payload.decisions; current = true; render(payload.as_of);
      message('workflow-mode', 'Current workflow loaded as of '+payload.as_of+
        '. Scan evidence remains as of '+seed.scan_as_of+'.');
    } catch (error) { setUnavailable(error.message); throw error; }
    finally { loading = false; find('workflow-refresh').disabled = false; }
  }
  function conditionalFields() {
    const status = form.elements.status.value;
    find('decision-owner').required = status !== 'Decision required';
    find('decision-due').required = status === 'Deferred';
    find('decision-notes').required = ['Deferred','False positive'].includes(status);
    [['decision-compensation', status === 'Compensating control'],
     ['decision-acceptance', status === 'Risk accepted']].forEach(([id, visible]) => {
      find(id).hidden = !visible;
      find(id).querySelectorAll('input,textarea').forEach(input => {
        input.disabled = !visible; input.required = visible;
      });
    });
  }
  function populate() {
    const state = states[editorKey], program = programs.find(p => p.key === editorKey);
    editorRevision = state.revision;
    find('workflow-title').textContent = program.title;
    const conflict = derived(program,state).evidence_conflict;
    find('workflow-evidence').textContent = 'Scan evidence as of '+seed.scan_as_of+
      ': '+program.failed_controls+' failed control(s). '+
      (conflict ? 'Evidence conflict — verification needs review.' :
       'This form cannot change the scan verdicts.');
    for (const field of ['owner','status','due_date','notes','compensating_control'])
      form.elements[field].value = state[field] || '';
    for (const field of ['rationale','approved_by','expires_at'])
      form.elements[field].value = (state.acceptance || {})[field] || '';
    conditionalFields();
    find('workflow-fields').disabled = !current;
    find('workflow-save').disabled = !current;
    find('workflow-reload').hidden = !live;
    const history = find('workflow-history'); history.replaceChildren();
    const changes = Array.isArray(state.history) ? state.history : [];
    changes.forEach(change => history.append(text('li', change.timestamp+' · '+change.field+
      ': '+JSON.stringify(change.from)+' → '+JSON.stringify(change.to))));
    if (!changes.length) history.append(text('li','No recorded changes.'));
    message('workflow-form-message', current ? 'Editing current workflow. Changes require Save decision.' :
      'Read-only snapshot. No durable save is available here.');
  }
  document.querySelectorAll('[data-edit-decision]').forEach(button => {
    button.addEventListener('click', () => {
      editorInstance++;
      editorKey = button.dataset.editDecision; editorOpener = button;
      find('workflow-reload').disabled = false;
      populate(); dialog.showModal(); find('workflow-title').focus();
    });
  });
  find('decision-status').addEventListener('change', conditionalFields);
  find('workflow-close').onclick = () => { if (!saving) dialog.close(); };
  dialog.addEventListener('keydown', event => {
    if (event.key !== 'Tab') return;
    const focusable = [...dialog.querySelectorAll(
      'button:enabled,input:enabled,select:enabled,textarea:enabled,a[href]')]
      .filter(node => node.getClientRects().length > 0);
    const first = focusable[0], last = focusable[focusable.length-1];
    if (!first) { event.preventDefault(); find('workflow-title').focus(); return; }
    if (!focusable.includes(document.activeElement) ||
        (event.shiftKey && document.activeElement === first) ||
        (!event.shiftKey && document.activeElement === last)) {
      event.preventDefault(); (event.shiftKey ? last : first).focus();
    }
  });
  dialog.addEventListener('cancel', event => { if (saving) event.preventDefault(); });
  dialog.addEventListener('close', () => { if (editorOpener) editorOpener.focus(); });
  find('workflow-reload').onclick = async () => {
    if (saving || loading) return;
    const instance = editorInstance;
    find('workflow-reload').disabled = true;
    find('workflow-fields').disabled = true;
    find('workflow-save').disabled = true;
    message('workflow-form-message','Workflow refresh is in progress; editing is paused.');
    try {
      await refresh();
      if (dialog.open && instance === editorInstance) populate();
    } catch (error) {
      if (dialog.open && instance === editorInstance)
        message('workflow-form-message', error.message, true);
    } finally {
      if (instance === editorInstance) find('workflow-reload').disabled = false;
    }
  };
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (loading) {
      message('workflow-form-message',
        'A workflow refresh is in progress. Wait for it to finish before saving.', true);
      return;
    }
    if (!live || !current || saving || !form.reportValidity()) return;
    const body = {decision_key:editorKey, expected_revision:editorRevision};
    for (const field of ['owner','status','due_date','notes','compensating_control'])
      body[field] = form.elements[field].value;
    body.acceptance = body.status === 'Risk accepted' ? {
      rationale:form.elements.rationale.value, approved_by:form.elements.approved_by.value,
      expires_at:form.elements.expires_at.value} : null;
    saving = true;
    find('workflow-fields').disabled = true; find('workflow-save').disabled = true;
    find('workflow-close').disabled = true; find('workflow-reload').disabled = true;
    form.setAttribute('aria-busy','true');
    message('workflow-form-message','Saving decision…');
    let saved = false;
    try {
      await request('POST',body); saved = true;
      await refresh();
      populate();
      message('workflow-form-message','Saved durably. Current workflow refreshed; scan evidence unchanged.');
      message('workflow-mode','Decision saved durably and current workflow refreshed. Scan evidence unchanged.');
    } catch (error) {
      if (error.status === 409 || !error.status || error.status >= 500) {
        current = false; find('workflow-save').disabled = true;
      }
      message('workflow-form-message', (saved ?
        'Saved on server, but refresh failed. Reload current workflow before continuing. ' :
        error.status === 409 ? 'Conflict: your draft was not saved. Reload and review before retrying. ' : '')+
        error.message, true);
      if (!current) setUnavailable(saved ? 'Save succeeded; current read failed.' :
        'Workflow must be reloaded before another save.');
    } finally {
      saving = false; form.removeAttribute('aria-busy');
      find('workflow-fields').disabled = !current;
      find('workflow-save').disabled = !current;
      find('workflow-close').disabled = false; find('workflow-reload').disabled = false;
    }
  });
  find('workflow-refresh').onclick = async () => { try { await refresh(); } catch (_) {} };
  find('workflow-connect').onclick = async () => {
    key = find('workflow-key').value.trim(); find('workflow-key').value = '';
    try { await refresh(); } catch (error) { message('workflow-mode',error.message,true); }
  };
  render(seed.scan_as_of);
  if (live) {
    find('workflow-auth').hidden = false; find('workflow-refresh').hidden = false;
    const url = new URL(location.href); key = url.searchParams.get('code') || '';
    if (key) { url.searchParams.delete('code'); history.replaceState(null,'',url); }
    setUnavailable('Live page: load current workflow to enable editing.');
    if (key) refresh().catch(() => {});
  }
  find('print-brief').onclick = () => window.print();
})();
"""
