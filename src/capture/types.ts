/**
 * Capture module types — MediaPipe Hands + ROI extraction.
 *
 * The capture pipeline runs entirely client-side (browser WebRTC).
 * Zero raw biometric data leaves the device.
 */

/** 2D point in image coordinates [0, imageWidth/Height]. */
export interface Point2D {
  x: number;
  y: number;
}

/** Single MediaPipe hand landmark (21 points per hand). */
export interface HandLandmark extends Point2D {
  z: number;
  /** Landmark index 0–20 per MediaPipe Hands specification. */
  index: number;
}

/**
 * Region of Interest extracted from a raw camera frame.
 * The ROI is a tight crop around the palm (landmarks 0–8 bounding box),
 * normalized and contrast-stretched.
 */
export interface PalmROI {
  /** Raw grayscale pixel data, row-major. */
  data: Uint8Array;
  width: number;
  height: number;
  /** Capture timestamp (Unix ms). Used for celestial entropy seed. */
  capturedAt: number;
  /** MediaPipe confidence score for this frame. */
  confidence: number;
}

/**
 * Extracted palm line segments in image space.
 * Each segment is an ordered list of points tracing the skeletonized line.
 */
export interface PalmLineSet {
  heart: Point2D[];
  head: Point2D[];
  life: Point2D[];
  fate: Point2D[];
  /** Intersection points between any two lines. */
  intersections: Point2D[];
  /** Source ROI dimensions for coordinate normalization. */
  roiWidth: number;
  roiHeight: number;
}

/** Capture session metadata for ANSSI-compatible audit logging. */
export interface CaptureSession {
  sessionId: string;
  deviceId: string;
  capturedAt: number;
  framesAnalyzed: number;
  bestFrameConfidence: number;
  mediapipeVersion: string;
}
