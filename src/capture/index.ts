/**
 * Capture module — MediaPipe Hands webcam capture + ROI extraction.
 *
 * Browser-only: requires navigator.mediaDevices (WebRTC) and
 * @mediapipe/hands (loaded via CDN script tag in the demo page).
 *
 * Processing pipeline:
 *   1. getUserMedia({ video: { width:640, height:480 } })
 *   2. VideoFrame → MediaPipe Hands → 21 landmarks per frame
 *   3. Collect N_FRAMES best-confidence frames, pick highest
 *   4. Palm ROI = bounding box of landmarks {0,1,5,9,13,17} + 20px padding
 *   5. Crop → OffscreenCanvas → getImageData → grayscale conversion
 *   6. Return 256×256 normalized grayscale PalmROI
 *
 * Zero raw biometric data leaves the browser.
 */

export type {
  Point2D,
  HandLandmark,
  PalmROI,
  PalmLineSet,
  CaptureSession,
} from "./types.js";

import type { PalmROI, HandLandmark } from "./types.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const VIDEO_WIDTH = 640;
const VIDEO_HEIGHT = 480;
const ROI_SIZE = 256;
const ROI_PADDING = 20;
/** Palm keypoint indices used for ROI bounding box. */
const PALM_KP = [0, 1, 5, 9, 13, 17];
/** Number of frames to collect before selecting best. */
const N_FRAMES = 15;

// ─── MediaPipe type shim (loaded via CDN at runtime) ─────────────────────────

/** Minimal interface for @mediapipe/hands Results (CDN script). */
interface MPHandsResults {
  multiHandLandmarks: Array<Array<{ x: number; y: number; z: number }>>;
  multiHandedness: Array<{ label: string; score: number }>;
}

type MPHandsInstance = {
  setOptions: (opts: Record<string, unknown>) => Promise<void>;
  onResults: (cb: (r: MPHandsResults) => void) => void;
  send: (inputs: { image: HTMLVideoElement }) => Promise<void>;
  close: () => void;
};

declare const Hands: new (opts: { locateFile: (f: string) => string }) => MPHandsInstance;

// ─── Internal state ───────────────────────────────────────────────────────────

let _stream: MediaStream | null = null;
let _video: HTMLVideoElement | null = null;
let _hands: MPHandsInstance | null = null;
let _ready = false;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** RGB/RGBA pixel → grayscale luminance (BT.601). */
function rgbaToGray(data: Uint8ClampedArray, width: number, height: number): Uint8Array {
  const gray = new Uint8Array(width * height);
  for (let i = 0, j = 0; i < data.length; i += 4, j++) {
    gray[j] = (0.299 * (data[i] ?? 0) + 0.587 * (data[i + 1] ?? 0) + 0.114 * (data[i + 2] ?? 0)) | 0;
  }
  return gray;
}

/** Bilinear resize of a grayscale Uint8Array to targetSize × targetSize. */
function resizeGray(
  src: Uint8Array,
  sw: number,
  sh: number,
  targetSize: number
): Uint8Array {
  const dst = new Uint8Array(targetSize * targetSize);
  const scaleX = sw / targetSize;
  const scaleY = sh / targetSize;
  for (let y = 0; y < targetSize; y++) {
    for (let x = 0; x < targetSize; x++) {
      const srcX = x * scaleX;
      const srcY = y * scaleY;
      const x0 = Math.floor(srcX);
      const y0 = Math.floor(srcY);
      const x1 = Math.min(x0 + 1, sw - 1);
      const y1 = Math.min(y0 + 1, sh - 1);
      const fx = srcX - x0;
      const fy = srcY - y0;
      const v =
        (src[y0 * sw + x0] ?? 0) * (1 - fx) * (1 - fy) +
        (src[y0 * sw + x1] ?? 0) * fx * (1 - fy) +
        (src[y1 * sw + x0] ?? 0) * (1 - fx) * fy +
        (src[y1 * sw + x1] ?? 0) * fx * fy;
      dst[y * targetSize + x] = v | 0;
    }
  }
  return dst;
}

/** Histogram-equalise a grayscale image (CLAHE approximation). */
function histEq(src: Uint8Array): Uint8Array {
  const hist = new Float64Array(256);
  for (const v of src) hist[v] = (hist[v] ?? 0) + 1;
  const cdf = new Float64Array(256);
  let cumul = 0;
  for (let i = 0; i < 256; i++) {
    cumul += hist[i] ?? 0;
    cdf[i] = cumul;
  }
  const min = cdf.find((v) => v > 0) ?? 0;
  const n = src.length;
  const dst = new Uint8Array(src.length);
  for (let i = 0; i < src.length; i++) {
    dst[i] = (((((cdf[src[i] ?? 0] ?? 0) - min) / (n - min)) * 255) | 0);
  }
  return dst;
}

/** Extract ROI from full camera frame given normalised landmark coordinates. */
function extractROI(
  frameData: Uint8ClampedArray,
  fw: number,
  fh: number,
  landmarks: Array<{ x: number; y: number }>
): { data: Uint8Array; roiWidth: number; roiHeight: number } {
  const palmKps = PALM_KP.map((i) => landmarks[i]).filter(Boolean) as Array<{ x: number; y: number }>;
  const xs = palmKps.map((p) => p.x * fw);
  const ys = palmKps.map((p) => p.y * fh);

  const minX = Math.max(0, Math.floor(Math.min(...xs)) - ROI_PADDING);
  const maxX = Math.min(fw, Math.ceil(Math.max(...xs)) + ROI_PADDING);
  const minY = Math.max(0, Math.floor(Math.min(...ys)) - ROI_PADDING);
  const maxY = Math.min(fh, Math.ceil(Math.max(...ys)) + ROI_PADDING);

  const roiWidth = maxX - minX;
  const roiHeight = maxY - minY;
  const gray = new Uint8Array(roiWidth * roiHeight);

  for (let y = 0; y < roiHeight; y++) {
    for (let x = 0; x < roiWidth; x++) {
      const fi = ((minY + y) * fw + (minX + x)) * 4;
      gray[y * roiWidth + x] =
        (0.299 * (frameData[fi] ?? 0) +
          0.587 * (frameData[fi + 1] ?? 0) +
          0.114 * (frameData[fi + 2] ?? 0)) | 0;
    }
  }
  return { data: gray, roiWidth, roiHeight };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Initialize the capture pipeline.
 * Starts the webcam stream, creates the hidden video element, and loads
 * MediaPipe Hands from the CDN (Hands must be available as a global).
 *
 * Call once at page load. Reuse across captures.
 */
export async function initCapture(): Promise<void> {
  if (_ready) return;

  _stream = await navigator.mediaDevices.getUserMedia({
    video: {
      width: { ideal: VIDEO_WIDTH },
      height: { ideal: VIDEO_HEIGHT },
      facingMode: "environment",
    },
    audio: false,
  });

  _video = document.createElement("video");
  _video.srcObject = _stream;
  _video.setAttribute("playsinline", "true");
  _video.muted = true;
  await _video.play();

  _hands = new Hands({
    locateFile: (f) =>
      `https://cdn.jsdelivr.net/npm/@mediapipe/hands@0.4.1675469240/${f}`,
  });

  await _hands.setOptions({
    maxNumHands: 1,
    modelComplexity: 1,
    minDetectionConfidence: 0.7,
    minTrackingConfidence: 0.5,
  });

  _ready = true;
}

/**
 * Capture a single-frame palm ROI using MediaPipe Hands.
 *
 * Processes N_FRAMES frames and returns the one with highest landmark
 * detection confidence. Rejects if no hand is detected in any frame.
 *
 * @param onProgress Optional callback fired after each frame (0.0..1.0).
 */
export async function captureROI(
  onProgress?: (fraction: number) => void
): Promise<PalmROI> {
  if (!_ready || !_video || !_hands) {
    throw new Error("capture.captureROI: call initCapture() first");
  }

  const canvas = new OffscreenCanvas(VIDEO_WIDTH, VIDEO_HEIGHT);
  const ctx = canvas.getContext("2d") as OffscreenCanvasRenderingContext2D | null;
  if (!ctx) throw new Error("OffscreenCanvas 2D not available");

  interface FrameResult {
    landmarks: Array<{ x: number; y: number; z: number }>;
    confidence: number;
    imageData: ImageData;
  }

  const frames: FrameResult[] = [];

  for (let fi = 0; fi < N_FRAMES; fi++) {
    await new Promise<void>((resolve) => {
      const handler = (results: MPHandsResults) => {
        const lms = results.multiHandLandmarks[0];
        const conf = results.multiHandedness[0]?.score ?? 0;
        if (lms && lms.length === 21) {
          ctx.drawImage(_video!, 0, 0, VIDEO_WIDTH, VIDEO_HEIGHT);
          const imgData = ctx.getImageData(0, 0, VIDEO_WIDTH, VIDEO_HEIGHT);
          frames.push({ landmarks: lms, confidence: conf, imageData: imgData });
        }
        resolve();
      };
      _hands!.onResults(handler);
      _hands!.send({ image: _video! }).catch(() => resolve());
    });
    onProgress?.((fi + 1) / N_FRAMES);
  }

  if (frames.length === 0) {
    throw new Error("No hand detected — ensure your palm is visible and well-lit");
  }

  const best = frames.reduce((a, b) => (a.confidence >= b.confidence ? a : b));
  const { data: frameData } = best.imageData;

  const { data: roiGray, roiWidth, roiHeight } = extractROI(
    frameData,
    VIDEO_WIDTH,
    VIDEO_HEIGHT,
    best.landmarks
  );

  // Resize to 256×256 + histogram equalisation
  const resized = resizeGray(roiGray, roiWidth, roiHeight, ROI_SIZE);
  const equalised = histEq(resized);

  // Map HandLandmarks to our type
  const handLandmarks: HandLandmark[] = best.landmarks.map((lm, idx) => ({
    x: lm.x * VIDEO_WIDTH,
    y: lm.y * VIDEO_HEIGHT,
    z: lm.z,
    index: idx,
  }));

  void handLandmarks; // stored for debugging; not in PalmROI interface

  return {
    data: equalised,
    width: ROI_SIZE,
    height: ROI_SIZE,
    capturedAt: Date.now(),
    confidence: best.confidence,
  };
}

/**
 * Stop the webcam stream and release all resources.
 */
export function stopCapture(): void {
  _hands?.close();
  _stream?.getTracks().forEach((t) => t.stop());
  _video?.remove();
  _hands = null;
  _stream = null;
  _video = null;
  _ready = false;
}
