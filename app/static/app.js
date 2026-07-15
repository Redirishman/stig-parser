(function () {
  'use strict';

  const resultsInput    = document.getElementById('results-input');
  const benchmarksInput = document.getElementById('benchmarks-input');
  const resultsZone     = document.getElementById('results-zone');
  const benchmarksZone  = document.getElementById('benchmarks-zone');
  const resultsFileList    = document.getElementById('results-file-list');
  const benchmarksFileList = document.getElementById('benchmarks-file-list');
  const resultsBrowse      = document.getElementById('results-browse');
  const benchmarksBrowse   = document.getElementById('benchmarks-browse');
  const resultsZoneNotice    = document.getElementById('results-zone-notice');
  const benchmarksZoneNotice = document.getElementById('benchmarks-zone-notice');
  const stallNote          = document.getElementById('stall-note');
  const processBtn      = document.getElementById('process-btn');
  const uploadForm      = document.getElementById('upload-form');
  const uploadSection   = document.getElementById('upload-section');
  const progressSection = document.getElementById('progress-section');
  const activityLog     = document.getElementById('activity-log');
  const warningsBox          = document.getElementById('warnings-box');
  const warningsList         = document.getElementById('warnings-list');
  const errorWarningsBox     = document.getElementById('error-warnings-box');
  const errorWarningsList    = document.getElementById('error-warnings-list');
  const resultSection   = document.getElementById('result-section');
  const resultSuccess   = document.getElementById('result-success');
  const resultError     = document.getElementById('result-error');
  const downloadLink    = document.getElementById('download-link');
  const errorMessage    = document.getElementById('error-message');

  let pollTimer = null;
  // Seeded from a server-rendered data attribute (strict CSP: no inline JS).
  let currentJobId = document.body.dataset.jobId || '';
  let lastWarnings = [];  // most recent warnings list, for showing on error
  let lastSummary = null; // findings summary from the completed job
  let pollFailures = 0;   // consecutive failed status fetches
  let lastProgressMsg = '';
  let unchangedPolls = 0; // consecutive polls with identical progress text

  // ------------------------------------------------------------------
  // File input + drag-and-drop
  // ------------------------------------------------------------------

  function removeFileAt(input, listEl, index) {
    // FileList is read-only; rebuild it via DataTransfer minus the chosen entry
    const dt = new DataTransfer();
    Array.from(input.files).forEach(function (f, i) {
      if (i !== index) dt.items.add(f);
    });
    input.files = dt.files;
    updateFileList(input, listEl);
  }

  function updateFileList(input, listEl) {
    listEl.innerHTML = '';
    Array.from(input.files).forEach(function (f, i) {
      const li = document.createElement('li');

      const nameSpan = document.createElement('span');
      nameSpan.className = 'file-name';
      nameSpan.textContent = f.name;
      li.appendChild(nameSpan);

      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'file-remove';
      removeBtn.setAttribute('aria-label', 'Remove ' + f.name);
      removeBtn.title = 'Remove';
      removeBtn.textContent = '✕';
      removeBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        removeFileAt(input, listEl, i);
      });
      li.appendChild(removeBtn);

      listEl.appendChild(li);
    });
    updateProcessBtn();
  }

  function showZoneNotice(noticeEl, msg) {
    noticeEl.textContent = msg;
    noticeEl.hidden = !msg;
  }

  function setupZone(zone, input, listEl, browseBtn, noticeEl, allowedExts) {
    browseBtn.addEventListener('click', function () {
      input.click();
    });

    zone.addEventListener('click', function (e) {
      // Whole zone opens the picker, except clicks on real controls
      // (browse button has its own handler; file rows have remove buttons).
      if (e.target.closest('button') || e.target.closest('.file-list')) return;
      input.click();
    });

    input.addEventListener('change', function () {
      showZoneNotice(noticeEl, '');
      updateFileList(input, listEl);
    });

    zone.addEventListener('dragover', function (e) {
      e.preventDefault();
      zone.classList.add('dragover');
    });

    zone.addEventListener('dragleave', function () {
      zone.classList.remove('dragover');
    });

    zone.addEventListener('drop', function (e) {
      e.preventDefault();
      zone.classList.remove('dragover');
      // Transfer dropped files into the input, filtering by allowed extensions
      const dt = new DataTransfer();
      let skipped = 0;
      Array.from(e.dataTransfer.files).forEach(function (f) {
        const lower = f.name.toLowerCase();
        if (allowedExts.some(function (ext) { return lower.endsWith(ext); })) {
          dt.items.add(f);
        } else {
          skipped++;
        }
      });
      input.files = dt.files;
      showZoneNotice(noticeEl, skipped > 0
        ? skipped + (skipped === 1 ? ' file skipped — only ' : ' files skipped — only ')
          + allowedExts.join(' / ') + ' accepted here.'
        : '');
      updateFileList(input, listEl);
    });
  }

  setupZone(resultsZone, resultsInput, resultsFileList, resultsBrowse, resultsZoneNotice, ['.xml', '.cklb', '.nessus']);
  setupZone(benchmarksZone, benchmarksInput, benchmarksFileList, benchmarksBrowse, benchmarksZoneNotice, ['.xml', '.zip']);

  function updateProcessBtn() {
    const hasResults = resultsInput.files && resultsInput.files.length > 0;
    processBtn.disabled = !hasResults;
    // Explain the disabled state; hide the hint once a results file is present.
    const hint = document.getElementById('process-hint');
    if (hint) hint.hidden = hasResults;
  }

  // ------------------------------------------------------------------
  // Form submission
  // ------------------------------------------------------------------

  uploadForm.addEventListener('submit', function (e) {
    e.preventDefault();
    const fd = new FormData(uploadForm);
    uploadSection.hidden = true;
    progressSection.hidden = false;
    resultSection.hidden = true;
    resultSuccess.hidden = true;
    resultError.hidden = true;
    warningsBox.hidden = true;
    warningsList.innerHTML = '';
    pollFailures = 0;
    unchangedPolls = 0;
    lastProgressMsg = '';
    stallNote.hidden = true;
    activityLog.innerHTML = '';
    logLine('Uploading files…');

    fetch('/api/process', { method: 'POST', body: fd })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) {
          showError(data.error);
          return;
        }
        currentJobId = data.job_id;
        startPolling(currentJobId);
      })
      .catch(function () {
        showError('Could not reach the server to upload files. Check that the app is still running, then try again.');
      });
  });

  // ------------------------------------------------------------------
  // Polling
  // ------------------------------------------------------------------

  function startPolling(jobId) {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(function () { poll(jobId); }, 1000);
  }

  // Append a timestamped line to the activity log (skips empty messages)
  function logLine(msg) {
    if (!msg) return;
    const line = document.createElement('div');
    line.className = 'log-line';

    const time = document.createElement('span');
    time.className = 'log-time';
    const now = new Date();
    time.textContent = [now.getHours(), now.getMinutes(), now.getSeconds()]
      .map(function (n) { return String(n).padStart(2, '0'); })
      .join(':');
    line.appendChild(time);

    line.appendChild(document.createTextNode(' ' + msg));
    activityLog.appendChild(line);
    activityLog.scrollTop = activityLog.scrollHeight;
  }

  function poll(jobId) {
    fetch('/api/status/' + jobId)
      .then(function (r) { return r.json(); })
      .then(function (data) {
        pollFailures = 0;

        // Capture warnings first so they're available to showError below
        showWarnings(data.warnings || []);

        // Log each new step; reassure the user if a step runs ~20s silent
        if ((data.progress || '') === lastProgressMsg) {
          unchangedPolls++;
          if (unchangedPolls >= 20) stallNote.hidden = false;
        } else {
          lastProgressMsg = data.progress || '';
          unchangedPolls = 0;
          stallNote.hidden = true;
          logLine(lastProgressMsg);
        }

        if (data.status === 'complete') {
          clearInterval(pollTimer);
          lastSummary = data.summary || null;
          showSuccess(jobId);
        } else if (data.status === 'cancelled') {
          clearInterval(pollTimer);
          softReset(); // back to the upload form; file selections kept
        } else if (data.status === 'error') {
          clearInterval(pollTimer);
          showError(data.error || 'An unknown error occurred.');
        } else if (data.error) {
          // 404 or other transport-level error from the status endpoint
          showError(data.error);
        }
      })
      .catch(function () {
        // Network hiccup — tolerate a few, then give up with a clear message
        pollFailures++;
        if (pollFailures >= 10) {
          showError('Lost contact with the server. The job may still be running — try reloading the page to reconnect.');
        }
      });
  }

  function showWarnings(warnings) {
    warnings = warnings || [];
    // Skip identical re-renders: the box is aria-live, and rebuilding it on
    // every poll would re-announce the same warnings to screen readers.
    const changed = JSON.stringify(warnings) !== JSON.stringify(lastWarnings);
    lastWarnings = warnings;
    if (warnings.length === 0 || !changed) return;
    warningsList.innerHTML = '';
    warnings.forEach(function (w) {
      const li = document.createElement('li');
      li.textContent = w;
      warningsList.appendChild(li);
    });
    warningsBox.hidden = false;
  }

  function showSuccess(jobId) {
    progressSection.hidden = true;
    resultSection.hidden = false;
    resultSuccess.hidden = false;
    downloadLink.href = '/api/download/' + jobId;
    renderSummary(lastSummary);
    // Warnings must survive into the end state — they gate whether the
    // report can go into an accreditation package as-is.
    const box = document.getElementById('success-warnings-box');
    const list = document.getElementById('success-warnings-list');
    list.innerHTML = '';
    if (lastWarnings && lastWarnings.length > 0) {
      lastWarnings.forEach(function (w) {
        const li = document.createElement('li');
        li.textContent = w;
        list.appendChild(li);
      });
      box.hidden = false;
    } else {
      box.hidden = true;
    }
  }

  function renderSummary(s) {
    const box = document.getElementById('report-summary');
    if (!s) {
      box.hidden = true;
      document.getElementById('summary-note').hidden = true;
      return;
    }
    document.getElementById('sum-files').textContent    = s.files;
    document.getElementById('sum-hosts').textContent    = s.hosts;
    document.getElementById('sum-findings').textContent = s.findings;
    document.getElementById('sum-cat1').textContent     = s.cat1;
    document.getElementById('sum-cat2').textContent     = s.cat2;
    document.getElementById('sum-cat3').textContent     = s.cat3;
    // CAT I count is the number that matters — flag it when non-zero
    const cat1Row = document.getElementById('sum-cat1').parentElement;
    cat1Row.classList.toggle('summary-cat1-open', s.cat1 > 0);
    // All-zero severity with findings present means benchmark matching
    // failed — surface that instead of letting 0/0/0 look like good news.
    document.getElementById('summary-note').hidden =
      !(s.findings > 0 && s.cat1 + s.cat2 + s.cat3 === 0);
    box.hidden = false;
  }

  function showError(msg) {
    if (pollTimer) clearInterval(pollTimer);
    progressSection.hidden = true;
    resultSection.hidden = false;
    resultError.hidden = false;
    errorMessage.textContent = msg;
    // Re-render warnings inside the error card so the user can see why
    errorWarningsList.innerHTML = '';
    if (lastWarnings && lastWarnings.length > 0) {
      lastWarnings.forEach(function (w) {
        const li = document.createElement('li');
        li.textContent = w;
        errorWarningsList.appendChild(li);
      });
      errorWarningsBox.hidden = false;
    } else {
      errorWarningsBox.hidden = true;
    }
  }

  // ------------------------------------------------------------------
  // Reset
  // ------------------------------------------------------------------

  // Shared section/status reset. Does NOT touch file selections.
  function resetSections() {
    currentJobId = '';
    lastWarnings = [];
    lastSummary = null;
    document.getElementById('report-summary').hidden = true;
    document.getElementById('summary-note').hidden = true;
    document.getElementById('success-warnings-box').hidden = true;
    document.getElementById('success-warnings-list').innerHTML = '';
    pollFailures = 0;
    unchangedPolls = 0;
    lastProgressMsg = '';
    stallNote.hidden = true;
    uploadSection.hidden = false;
    progressSection.hidden = true;
    resultSection.hidden = true;
    resultSuccess.hidden = true;
    resultError.hidden = true;
    warningsBox.hidden = true;
    warningsList.innerHTML = '';
    errorWarningsBox.hidden = true;
    errorWarningsList.innerHTML = '';
    activityLog.innerHTML = '';
    document.getElementById('cancel-btn').disabled = false;
  }

  // Full reset after a successful run: clear file selections too.
  function resetUI() {
    resetSections();
    resultsFileList.innerHTML = '';
    benchmarksFileList.innerHTML = '';
    resultsInput.value = '';
    benchmarksInput.value = '';
    showZoneNotice(resultsZoneNotice, '');
    showZoneNotice(benchmarksZoneNotice, '');
    updateProcessBtn(); // files just cleared → disabled + hint reshown
  }

  // Soft reset after an error: keep the user's file selections intact.
  function softReset() {
    resetSections();
    updateProcessBtn();
  }

  document.getElementById('reset-btn').addEventListener('click', resetUI);
  document.getElementById('reset-btn-error').addEventListener('click', softReset);

  const cancelBtn = document.getElementById('cancel-btn');
  cancelBtn.addEventListener('click', function () {
    if (!currentJobId) return;
    cancelBtn.disabled = true;
    logLine('Cancelling…');
    fetch('/api/cancel/' + currentJobId, { method: 'POST' })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        // Job may have finished before the cancel landed — let polling
        // handle "complete"/"error"; "cancelled" also arrives via polling.
        if (data.error) cancelBtn.disabled = false;
      })
      .catch(function () {
        cancelBtn.disabled = false;
      });
  });

  // ------------------------------------------------------------------
  // Reconnect to an in-progress job from a previous page load
  // ------------------------------------------------------------------

  if (currentJobId) {
    fetch('/api/status/' + currentJobId)
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data.error && (data.status === 'running' || data.status === 'complete')) {
          uploadSection.hidden = true;
          progressSection.hidden = false;
          if (data.status === 'complete') {
            lastSummary = data.summary || null;
            showSuccess(currentJobId);
          } else {
            logLine('Reconnected to running job…');
            startPolling(currentJobId);
          }
        }
      })
      .catch(function () { /* no active job — show upload form */ });
  }

})();
