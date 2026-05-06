#!/usr/bin/env node
// Self-test for web/vad.js. Exercises the pure-DSP surface (no AudioContext).
//
// Run: node server/tm/_test/test-vad.mjs

import { strict as assert } from 'node:assert';
import {
  frameRms,
  frameZcr,
  SpeakerMfcc,
  pickAudioBitrate,
  pickMaxClipMs
} from '../../../web/vad.js';

function ok(label) { process.stdout.write(`[ok] ${label}\n`); }

function makeSine(freq, sr, durationS, amp) {
  if (amp == null) amp = 0.3;
  const n = Math.round(sr * durationS);
  const out = new Float32Array(n);
  for (let i = 0; i < n; i++) out[i] = amp * Math.sin(2 * Math.PI * freq * i / sr);
  return out;
}

function makeSilence(sr, durationS) {
  return new Float32Array(Math.round(sr * durationS));
}

// 1. Energy: synthetic sine passes voice threshold; silence does not.
{
  const sr = 16000;
  const sine = makeSine(500, sr, 1.0, 0.3);
  const eVoice = frameRms(sine);
  assert.ok(
    eVoice > 0.005,
    `expected voice RMS ${eVoice} > voiceThresholdEnergy 0.005`
  );
  const silence = makeSilence(sr, 1.0);
  const eSilence = frameRms(silence);
  assert.ok(
    eSilence < 0.002,
    `expected silence RMS ${eSilence} < silenceThresholdEnergy 0.002`
  );
  // ZCR sanity: a 500 Hz sine at 16 kHz over 800 samples (50 ms) gives ~50 zero
  // crossings, which sits inside [voiceZcrMin=10, voiceZcrMax=120].
  const win = sine.subarray(0, 800);
  const z = frameZcr(win);
  assert.ok(z >= 10 && z <= 120, `zcr ${z} inside voice band [10, 120]`);
  ok(`frameRms voice=${eVoice.toFixed(4)} silence=${eSilence.toFixed(4)} zcr=${z}`);
}

// 2. SpeakerMfcc: same signal twice -> cosine > 0.95.
// 3. SpeakerMfcc: distinct signals -> cosine < 0.7.
{
  const sr = 16000;
  const sm = new SpeakerMfcc();
  const sigA = makeSine(400, sr, 1.5, 0.3);
  const sigAcopy = makeSine(400, sr, 1.5, 0.3);
  const sigB = makeSine(3500, sr, 1.5, 0.3);

  const tmplA = sm.enroll(sigA, sr);
  assert.equal(tmplA.length, 13, 'template is 13-dim');
  assert.ok(tmplA instanceof Float32Array, 'template is Float32Array');

  const cosSame = sm.match(tmplA, sigAcopy, sr);
  assert.ok(cosSame > 0.95, `same signal cosine ${cosSame} > 0.95`);
  ok(`SpeakerMfcc same: ${cosSame.toFixed(4)} > 0.95`);

  const cosDiff = sm.match(tmplA, sigB, sr);
  assert.ok(cosDiff < 0.7, `distinct signals cosine ${cosDiff} < 0.7`);
  ok(`SpeakerMfcc different: ${cosDiff.toFixed(4)} < 0.7`);
}

// 4. pickAudioBitrate: slow-2g -> 0; 2g -> 4000; 3g -> 8000; 4g/unknown -> 12000.
{
  assert.equal(pickAudioBitrate({ connection: { effectiveType: 'slow-2g' } }), 0);
  assert.equal(pickAudioBitrate({ connection: { effectiveType: '2g' } }), 4000);
  assert.equal(pickAudioBitrate({ connection: { effectiveType: '3g' } }), 8000);
  assert.equal(pickAudioBitrate({ connection: { effectiveType: '4g' } }), 12000);
  assert.equal(pickAudioBitrate({}), 12000);
  assert.equal(pickAudioBitrate(null), 12000);
  ok('pickAudioBitrate: slow-2g=0; 2g=4000; 3g=8000; 4g/unknown=12000');

  assert.equal(pickMaxClipMs({ connection: { effectiveType: '2g' } }), 10000);
  assert.equal(pickMaxClipMs({ connection: { effectiveType: '3g' } }), 30000);
  assert.equal(pickMaxClipMs({ connection: { effectiveType: '4g' } }), 30000);
  assert.equal(pickMaxClipMs({}), 30000);
  ok('pickMaxClipMs: 2g=10000; otherwise=30000');
}

process.stdout.write('OK\n');
