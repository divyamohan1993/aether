// Aether field-mode VAD + speaker gate. Pure ES module. No external deps.
//
// Surface:
//   class EnergyZcrVad   energy + zero-crossing VAD over an AnalyserNode pump.
//   class SpeakerMfcc    13-dim mean MFCC template + cosine match.
//   pickAudioBitrate(nav)   adaptive Opus bitrate by navigator.connection.effectiveType.
//   pickMaxClipMs(nav)      shorter clip cap on 2g.
//
// Pure DSP helpers (frameRms, frameZcr, mfccFrame, meanMfcc, cosineSim01) are
// exported so the test suite can exercise the math without an AudioContext.

// ---------- pure DSP primitives ----------

export function frameRms(samples) {
  const n = samples.length;
  if (n === 0) return 0;
  let s = 0;
  for (let i = 0; i < n; i++) s += samples[i] * samples[i];
  return Math.sqrt(s / n);
}

export function frameZcr(samples) {
  const n = samples.length;
  if (n < 2) return 0;
  let zc = 0;
  let prev = samples[0] >= 0;
  for (let i = 1; i < n; i++) {
    const cur = samples[i] >= 0;
    if (cur !== prev) zc++;
    prev = cur;
  }
  return zc;
}

// In-place radix-2 Cooley-Tukey FFT. Caller pads to power of two.
function fft(re, im) {
  const n = re.length;
  let j = 0;
  for (let i = 1; i < n; i++) {
    let bit = n >> 1;
    while (j & bit) { j ^= bit; bit >>= 1; }
    j ^= bit;
    if (i < j) {
      const tr = re[i]; re[i] = re[j]; re[j] = tr;
      const ti = im[i]; im[i] = im[j]; im[j] = ti;
    }
  }
  for (let len = 2; len <= n; len <<= 1) {
    const half = len >> 1;
    const ang = -2 * Math.PI / len;
    const wpr = Math.cos(ang);
    const wpi = Math.sin(ang);
    for (let i = 0; i < n; i += len) {
      let cr = 1, ci = 0;
      for (let k = 0; k < half; k++) {
        const a = i + k;
        const b = a + half;
        const tr = cr * re[b] - ci * im[b];
        const ti = cr * im[b] + ci * re[b];
        re[b] = re[a] - tr;
        im[b] = im[a] - ti;
        re[a] += tr;
        im[a] += ti;
        const ncr = cr * wpr - ci * wpi;
        const nci = cr * wpi + ci * wpr;
        cr = ncr; ci = nci;
      }
    }
  }
}

function nextPow2(n) { let p = 1; while (p < n) p <<= 1; return p; }

function hzToMel(f) { return 2595 * Math.log10(1 + f / 700); }
function melToHz(m) { return 700 * (Math.pow(10, m / 2595) - 1); }

function buildMelFilterbank(numFilters, fftSize, sampleRate) {
  const numBins = (fftSize >> 1) + 1;
  const lowMel = hzToMel(0);
  const highMel = hzToMel(sampleRate / 2);
  const points = new Float32Array(numFilters + 2);
  for (let i = 0; i < points.length; i++) {
    points[i] = melToHz(lowMel + (i / (numFilters + 1)) * (highMel - lowMel));
  }
  const bins = new Int32Array(numFilters + 2);
  for (let i = 0; i < points.length; i++) {
    bins[i] = Math.min(numBins - 1, Math.max(0, Math.floor((fftSize + 1) * points[i] / sampleRate)));
  }
  const filters = new Array(numFilters);
  for (let m = 0; m < numFilters; m++) {
    const f = new Float32Array(numBins);
    const lo = bins[m], mid = bins[m + 1], hi = bins[m + 2];
    for (let k = lo; k < mid; k++) if (mid > lo) f[k] = (k - lo) / (mid - lo);
    for (let k = mid; k < hi; k++) if (hi > mid) f[k] = (hi - k) / (hi - mid);
    filters[m] = f;
  }
  return filters;
}

function hammingWindow(N) {
  const w = new Float32Array(N);
  if (N === 1) { w[0] = 1; return w; }
  const denom = N - 1;
  for (let i = 0; i < N; i++) w[i] = 0.54 - 0.46 * Math.cos((2 * Math.PI * i) / denom);
  return w;
}

function dct2(input, numCoeffs) {
  const N = input.length;
  const out = new Float32Array(numCoeffs);
  const piOverN = Math.PI / N;
  for (let k = 0; k < numCoeffs; k++) {
    let s = 0;
    for (let n = 0; n < N; n++) s += input[n] * Math.cos(piOverN * (n + 0.5) * k);
    out[k] = s;
  }
  return out;
}

export function mfccFrame(frame, sampleRate, opts) {
  const numFilters = (opts && opts.numFilters) || 25;
  const numCoeffs = (opts && opts.numCoeffs) || 13;
  const fftSize = nextPow2(frame.length);
  const re = new Float32Array(fftSize);
  const im = new Float32Array(fftSize);
  const win = hammingWindow(frame.length);
  for (let i = 0; i < frame.length; i++) re[i] = frame[i] * win[i];
  fft(re, im);
  const numBins = (fftSize >> 1) + 1;
  const power = new Float32Array(numBins);
  for (let k = 0; k < numBins; k++) power[k] = re[k] * re[k] + im[k] * im[k];
  const filters = buildMelFilterbank(numFilters, fftSize, sampleRate);
  const melLog = new Float32Array(numFilters);
  for (let m = 0; m < numFilters; m++) {
    let s = 0;
    const f = filters[m];
    for (let k = 0; k < numBins; k++) s += power[k] * f[k];
    melLog[m] = Math.log(Math.max(s, 1e-10));
  }
  return dct2(melLog, numCoeffs);
}

export function meanMfcc(samples, sampleRate, opts) {
  const numFilters = (opts && opts.numFilters) || 25;
  const numCoeffs = (opts && opts.numCoeffs) || 13;
  const frameLen = Math.max(64, Math.round(0.025 * sampleRate));
  const hopLen = Math.max(32, Math.round(0.010 * sampleRate));
  const out = new Float32Array(numCoeffs);
  let count = 0;
  for (let start = 0; start + frameLen <= samples.length; start += hopLen) {
    const frame = samples.subarray(start, start + frameLen);
    if (frameRms(frame) < 1e-4) continue;
    const c = mfccFrame(frame, sampleRate, { numFilters, numCoeffs });
    for (let i = 0; i < numCoeffs; i++) out[i] += c[i];
    count++;
  }
  if (count > 0) for (let i = 0; i < numCoeffs; i++) out[i] /= count;
  return out;
}

// Cosine similarity mapped to [0..1] via (1+cos)/2.
// First coefficient (c0, log overall energy) is skipped by default — speaker
// timbre lives in c1..c12; c0 mostly tracks loudness.
export function cosineSim01(a, b, skipFirst) {
  const skip = skipFirst === false ? 0 : 1;
  const n = Math.min(a.length, b.length);
  let dot = 0, na = 0, nb = 0;
  for (let i = skip; i < n; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (na === 0 || nb === 0) return 0;
  const c = dot / (Math.sqrt(na) * Math.sqrt(nb));
  const mapped = (1 + c) / 2;
  return mapped < 0 ? 0 : mapped > 1 ? 1 : mapped;
}

// ---------- speaker gate ----------

export class SpeakerMfcc {
  constructor(opts) {
    this.numFilters = (opts && opts.numFilters) || 25;
    this.numCoeffs = (opts && opts.numCoeffs) || 13;
  }
  enroll(samples, sampleRate) {
    return meanMfcc(samples, sampleRate, { numFilters: this.numFilters, numCoeffs: this.numCoeffs });
  }
  // Accepts a Float32Array template (legacy) OR an object {template:[...]} from
  // the new multi-sample form. Returns cosine similarity in [0..1].
  match(template, samples, sampleRate) {
    const obs = this.enroll(samples, sampleRate);
    const tpl = template && template.template ? template.template : template;
    return cosineSim01(tpl, obs);
  }
}

// Average N MFCC vectors (Float32Array or number[]) into one Float32Array.
// Used by the 3-sample voice enrolment flow so loud/calm/normal speech all
// contribute equally. Drops empty inputs.
export function averageTemplates(vectors) {
  const valid = (vectors || []).filter(v => v && v.length);
  if (!valid.length) return new Float32Array(0);
  const n = valid[0].length;
  const out = new Float32Array(n);
  for (const v of valid) for (let i = 0; i < n; i++) out[i] += v[i] || 0;
  for (let i = 0; i < n; i++) out[i] /= valid.length;
  return out;
}

// ---------- network-aware audio params ----------

export function pickAudioBitrate(nav) {
  // Adaptive verbosity by reachable bandwidth. Higher network grade lets
  // us send richer audio (more samples) so SDRF triangulates harder; on
  // slow-2g return 0 and the client falls back to a text-only heartbeat.
  // Downlink Mbps (Network Information API) flags wifi / 5G capacity.
  const c = nav && nav.connection;
  const eff = c && c.effectiveType;
  const downlinkMbps = c && Number.isFinite(c.downlink) ? c.downlink : null;
  if (eff === 'slow-2g') return 0;
  if (eff === '2g') return 4000;
  if (eff === '3g') return 8000;
  if (downlinkMbps !== null && downlinkMbps >= 5) return 24000;
  return 16000;
}

export function pickMaxClipMs(nav) {
  const c = nav && nav.connection;
  const eff = c && c.effectiveType;
  const downlinkMbps = c && Number.isFinite(c.downlink) ? c.downlink : null;
  if (eff === '2g') return 10000;
  if (eff === '3g') return 20000;
  if (downlinkMbps !== null && downlinkMbps >= 5) return 45000;
  return 30000;
}

// Choose telemetry verbosity by network grade. Slow-2g sends only what
// fits in a single GSM burst; high-bandwidth attaches every detail.
export function pickTelemetryProfile(nav) {
  const c = nav && nav.connection;
  const eff = c && c.effectiveType;
  if (eff === 'slow-2g') return { level: 'minimal', pressure: false, motion: false, bt: false, altitude: false, speed: false };
  if (eff === '2g')      return { level: 'compact', pressure: true,  motion: false, bt: false, altitude: true,  speed: false };
  if (eff === '3g')      return { level: 'standard', pressure: true, motion: true,  bt: false, altitude: true,  speed: true };
  return { level: 'full', pressure: true, motion: true, bt: true, altitude: true, speed: true };
}

// ---------- VAD class ----------
//
// Frame loop pulls time-domain samples from an AnalyserNode every frameMs.
// First calibrateMs of audio sets the ambient baseline; thresholds bump up
// to max(spec default, 4× ambient RMS) for voice and 2× ambient for silence.
//
// State machine:
//   idle  + 3 voice frames in a row             -> phrase-start, enter active
//   active + 30 silence frames in a row         -> phrase-end, expose phraseBuffer

export class EnergyZcrVad extends EventTarget {
  constructor(opts) {
    super();
    const o = opts || {};
    this.frameMs = o.frameMs || 50;
    this.voiceThresholdEnergy = o.voiceThresholdEnergy != null ? o.voiceThresholdEnergy : 0.005;
    this.silenceThresholdEnergy = o.silenceThresholdEnergy != null ? o.silenceThresholdEnergy : 0.002;
    this.voiceZcrMin = o.voiceZcrMin != null ? o.voiceZcrMin : 10;
    this.voiceZcrMax = o.voiceZcrMax != null ? o.voiceZcrMax : 120;
    this.calibrateMs = o.calibrateMs != null ? o.calibrateMs : 2000;
    this.phraseBuffer = new Float32Array(0);

    this._ctx = null;
    this._analyser = null;
    this._stream = null;
    this._timer = null;
    this._tmp = null;
    this._frameLen = 0;
    this._voiceFrames = 0;
    this._silenceFrames = 0;
    this._inPhrase = false;
    this._calibrating = true;
    this._calibrateAccum = [];
    this._calibrateStartMs = 0;
    this._phraseFrames = [];
  }

  async start(stream) {
    if (this._ctx) return;
    this._stream = stream;
    const AC = globalThis.AudioContext || globalThis.webkitAudioContext;
    if (!AC) throw new Error('audio_context_unavailable');
    this._ctx = new AC();
    if (this._ctx.state === 'suspended') await this._ctx.resume();
    const src = this._ctx.createMediaStreamSource(stream);
    this._analyser = this._ctx.createAnalyser();
    this._analyser.fftSize = 2048;
    this._analyser.smoothingTimeConstant = 0;
    src.connect(this._analyser);
    const sr = this._ctx.sampleRate;
    this._frameLen = Math.max(256, Math.round(sr * this.frameMs / 1000));
    this._tmp = new Float32Array(this._analyser.fftSize);
    this._calibrateStartMs = (globalThis.performance && performance.now()) || Date.now();
    this._tick();
  }

  stop() {
    if (this._timer) { clearTimeout(this._timer); this._timer = null; }
    if (this._ctx) {
      try { this._ctx.close(); } catch (_) { /* ignore */ }
      this._ctx = null;
    }
    this._analyser = null;
    this._stream = null;
  }

  _tick() {
    if (!this._analyser) return;
    this._analyser.getFloatTimeDomainData(this._tmp);
    const f = new Float32Array(this._frameLen);
    const start = Math.max(0, this._tmp.length - f.length);
    for (let i = 0; i < f.length; i++) f[i] = this._tmp[start + i] || 0;
    this._processFrame(f);
    this._timer = setTimeout(() => this._tick(), this.frameMs);
  }

  _processFrame(frame) {
    const e = frameRms(frame);
    const z = frameZcr(frame);
    const now = (globalThis.performance && performance.now()) || Date.now();
    const elapsed = now - this._calibrateStartMs;

    if (this._calibrating) {
      this._calibrateAccum.push(e);
      if (elapsed >= this.calibrateMs) {
        let sum = 0;
        for (const v of this._calibrateAccum) sum += v;
        const ambient = sum / Math.max(1, this._calibrateAccum.length);
        this.voiceThresholdEnergy = Math.max(this.voiceThresholdEnergy, ambient * 4);
        this.silenceThresholdEnergy = Math.max(this.silenceThresholdEnergy, ambient * 2);
        this._calibrateAccum = null;
        this._calibrating = false;
      }
      return;
    }

    const isVoice = e > this.voiceThresholdEnergy &&
                    z >= this.voiceZcrMin && z <= this.voiceZcrMax;
    const isSilence = e < this.silenceThresholdEnergy;

    if (isVoice) { this._voiceFrames++; this._silenceFrames = 0; }
    else if (isSilence) { this._silenceFrames++; this._voiceFrames = 0; }

    if (!this._inPhrase && this._voiceFrames >= 3) {
      this._inPhrase = true;
      this._phraseFrames = [new Float32Array(frame)];
      this.dispatchEvent(new Event('phrase-start'));
    } else if (this._inPhrase) {
      this._phraseFrames.push(new Float32Array(frame));
      if (this._silenceFrames >= 30) {
        let total = 0;
        for (const fr of this._phraseFrames) total += fr.length;
        const out = new Float32Array(total);
        let off = 0;
        for (const fr of this._phraseFrames) { out.set(fr, off); off += fr.length; }
        this.phraseBuffer = out;
        this._inPhrase = false;
        this._phraseFrames = [];
        this.dispatchEvent(new Event('phrase-end'));
      }
    }
  }
}
