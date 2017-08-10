'use strict';

var API = 'api'

function onsubmit(e) {
  e.preventDefault();
  var input = document.querySelector('.domain input');
  var button = document.querySelector('.domain button');
  var result = document.querySelector('#result');

  button.disabled = true;
  result.innerHTML = document.querySelector('#templates > .loading').innerHTML;

  var domain = input.value;
  var xhr = new XMLHttpRequest();
  xhr.open('GET', API+'?domain='+domain);
  xhr.send();
  xhr.onload = function() {
    button.disabled = false;
    if (xhr.status == 429) {
      result.innerHTML = document.querySelector('#templates > .rate-limit').innerHTML;
    } else if (xhr.status != 200) {
      result.innerHTML = document.querySelector('#templates > .other-error').innerHTML;
    } else {
      result.innerHTML = xhr.responseText;
    }
  };
  xhr.onerror = function(e) {
    button.disabled = false;
    console.error('could not finish XHR', e);
    result.innerHTML = document.querySelector('#templates > .other-error').innerHTML;
  };
}

function onload() {
  document.querySelector('form.domain').addEventListener('submit', onsubmit);
}

onload();
