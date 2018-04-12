'use strict';

var API = 'api'

var input = document.querySelector('.domain input');
var button = document.querySelector('.domain button');
var summary = document.querySelector('#summary');
var report = document.querySelector('#report');

function onsubmit(e) {
  e.preventDefault();

  button.disabled = true;
  summary.innerHTML = document.querySelector('#templates > .loading').innerHTML;
  report.innerHTML = document.querySelector('#templates > .template-report').innerHTML;

  var domain = input.value;
  var url = API+'?domain='+domain;

  if ('EventSource' in window) {
    var events = new EventSource(url);
    events.onmessage = function(e) {
      var message = JSON.parse(e.data);
      onmessage(message);
      if (message.close) {
        events.close();
      }
    };
    events.onerror = function(e) {
      console.error('onerror', e);
      button.disabled = false;
      summary.innerHTML = document.querySelector('#templates > .other-error').innerHTML;
      // TODO: summary.innerHTML = document.querySelector('#templates > .rate-limit').innerHTML;
      events.close();
    };
  } else {
    console.log('using fallback for EventSource');
    // Fallback for IE/Edge
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url);
    var done = 0;
    var message = '';

    function incomingData() {
      var lines = xhr.responseText.split('\n');
      for (var i=done; i<lines.length; i++) {
        var line = lines[i].trim();
        if (line.substr(0, 6) == 'data: ') {
          message += line.substr(6);
        } else if (!line) {
          done = i;
          if (message) {
            onmessage(JSON.parse(message));
            message = '';
          }
        }
        if (message) {
          onmessage(JSON.parse(message));
          message = '';
        }
      }
    }

    xhr.onprogress = function(e) {
      incomingData();
    };
    xhr.onload = function(e) {
      button.disabled = false;
      incomingData();
    }
    xhr.onerror = function(e) {
      button.disabled = false;
      if (e.status == 429) {
        summary.innerHTML = document.querySelector('#templates > .rate-limit').innerHTML;
      } else {
        summary.innerHTML = document.querySelector('#templates > .other-error').innerHTML;
      }
    };
    xhr.send();
  }
}

function onmessage(message) {
  if (message.summary) {
    summary.innerHTML = message.summary;
  }
  if (message.reportName) {
    var div = report.querySelector('.report-' + message.reportName);
    if (message.part) {
      div.querySelector('.parts').innerHTML += message.part;
    } else if (message.html) {
      div.querySelector('.contents').innerHTML = message.html;
    }
    if (message.verdict) {
      div.querySelector('h3').classList.remove('loading');
      div.querySelector('h3').classList.add(message.verdict);
    }
  }
  if (message.close) {
    button.disabled = false;
  }
}

function onload() {
  document.querySelector('form.domain').addEventListener('submit', onsubmit);
}

onload();
