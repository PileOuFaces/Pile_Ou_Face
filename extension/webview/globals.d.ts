/**
 * Type declarations for VS Code webview globals and POF hub window/globalThis properties.
 * These are plain-browser-globals injected by the VS Code webview runtime and
 * by the hub script files — no bundler is involved.
 */

// ---------------------------------------------------------------------------
// VS Code webview runtime global
// ---------------------------------------------------------------------------

/** VS Code webview API factory, available only inside a VS Code webview context. */
declare function acquireVsCodeApi(): {
  postMessage(message: unknown): void;
  getState(): unknown;
  setState(state: unknown): void;
};

// ---------------------------------------------------------------------------
// POF hub globals — assigned on window *and* on globalThis (UMD-style modules)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Shared message types used across hub files
// ---------------------------------------------------------------------------

/** Generic hub message with a required type discriminant. */
interface HubMessage {
  type: string;
  [key: string]: any;
}

/** Controller interface for the message router. */
interface HubController {
  handleMessage?: (msg: HubMessage) => boolean | void;
  handleBinarySourceMessage?: (msg: HubMessage) => boolean | void;
  handleVisualizerMessage?: (msg: HubMessage) => boolean | void;
  handleHistoryMessage?: (msg: HubMessage) => boolean | void;
  handleFilePayloadMessage?: (msg: HubMessage) => boolean | void;
  handlePwntoolsMessage?: (msg: HubMessage) => boolean | void;
  handlePreviewMessage?: (msg: HubMessage) => boolean | void;
}

/** Fallback vscode stub shape used when acquireVsCodeApi is unavailable. */
interface VsCodeApiOrStub {
  postMessage(message?: unknown): void;
  getState?(): unknown;
  setState?(state: unknown): void;
}

interface Window {
  /** Hub state helpers (shared/hubState.js) */
  POFHubState: {
    STORAGE_KEY: string;
    loadStorage(): Record<string, unknown>;
    saveStorage(updates: Record<string, unknown>): Record<string, unknown>;
  };

  /** VS Code message bridge (shared/messageBus.js) */
  POFHubMessageBus: {
    vscode: VsCodeApiOrStub;
    postMessage(message: unknown): void;
    onMessage(listener: (event: MessageEvent) => void): () => void;
  };

  /** Message router factory (shared/messageRouter.js) */
  POFHubMessageRouter: {
    initMessageRouter(deps?: unknown): {
      handleMessage(message: unknown): boolean;
      registerController(controller: unknown): unknown;
    };
  };

  /** Payload preview helpers (shared/payloadPreview.js) */
  PofPayloadPreview: unknown;

  /** Payload core helpers (static/payloadCore.js) */
  POFHubPayloadCore: unknown;

  /** General POF hub namespace used by several modules */
  POFHub: Record<string, unknown>;

  /** Safe Markdown renderer for assistant responses. */
  POFMarkdownRenderer: {
    renderMarkdown(container: Element, markdown: string, doc?: Document): void;
  };

  /** Conversation branching helpers used by edit and regenerate actions. */
  POFChatMessageActions: {
    prepareRegeneration(messages: unknown[], assistantIndex: number): {
      context: unknown[];
      prompt: string;
      model: string;
      sourceIndex: number;
    } | null;
    prepareMessageEdit(messages: unknown[], userIndex: number, nextContent: string): {
      context: unknown[];
      prompt: string;
      model: string;
      sourceIndex: number;
    } | null;
  };

  /** Serializes the active AI conversation for Markdown and JSON exports. */
  POFChatExport: {
    buildConversationExport(options: Record<string, unknown>): Record<string, unknown>;
    buildSuggestedName(title: string): string;
    formatConversationMarkdown(snapshot: Record<string, unknown>): string;
  };

  /** Search, sort and rename helpers for local AI conversation history. */
  POFChatHistory: {
    filterAndSortConversations(
      history: unknown[],
      query?: string,
      sort?: string,
    ): unknown[];
    normalizeConversationTitle(title: string): string;
  };

  /** Estimates and reports the conversation context sent to AI providers. */
  POFChatContextBudget: {
    buildContextWindow(messages: unknown[], options?: Record<string, number>): {
      lines: string[];
      sourceMessages: number;
      includedMessages: number;
      omittedMessages: number;
      clippedMessages: number;
      omittedChars: number;
      contextChars: number;
      estimatedTokens: number;
      truncated: boolean;
      significantTruncation: boolean;
    };
    estimateTokens(textOrLength: string | number): number;
    formatBudgetLabel(budget: Record<string, unknown>): string;
    formatTruncationWarning(budget: Record<string, unknown>): string;
  };

  /** Normalizes generation settings shared by Ollama and cloud providers. */
  POFAiGenerationSettings: {
    DEFAULTS: {
      temperature: number;
      top_p: number;
      max_tokens: number;
    };
    fromGlobalSettings(settings: Record<string, unknown>): {
      temperature: number;
      top_p: number;
      max_tokens: number;
    };
    normalize(settings: Record<string, unknown>, fallback?: Record<string, number>): {
      temperature: number;
      top_p: number;
      max_tokens: number;
    };
  };

  /** Matches dated model pricing rules and estimates token costs. */
  POFAiPricing: {
    estimateConversationCost(
      messages: unknown[],
      rules: unknown[],
      normalizeUsage?: (usage: unknown) => unknown,
    ): {
      totalCost: number;
      pricedMessages: number;
      unpricedMessages: number;
      currency: string;
    };
    estimateUsageCost(
      usage: unknown,
      model: string,
      rules: unknown[],
    ): Record<string, unknown> | null;
    formatUsd(value: number): string;
    normalizeRules(rules: unknown[]): unknown[];
  };
}

// UMD-style files use `globalThis` as root — declare the same properties there.
declare var POFHubState: Window["POFHubState"];
declare var POFHubMessageBus: Window["POFHubMessageBus"];
declare var POFHubMessageRouter: Window["POFHubMessageRouter"];
declare var PofPayloadPreview: Window["PofPayloadPreview"];
declare var POFHubPayloadCore: Window["POFHubPayloadCore"];
declare var POFHub: Window["POFHub"];

// Augment the globalThis type so that UMD wrappers using
// `typeof globalThis !== 'undefined' ? globalThis : this`
// as their root argument satisfy property-assignment checks.
declare namespace globalThis {
  var POFHubState: Window["POFHubState"];
  var POFHubMessageBus: Window["POFHubMessageBus"];
  var POFHubMessageRouter: Window["POFHubMessageRouter"];
  var PofPayloadPreview: Window["PofPayloadPreview"];
  var POFHubPayloadCore: Window["POFHubPayloadCore"];
  var POFHub: Window["POFHub"];
}

// ---------------------------------------------------------------------------
// Array.prototype.includes widening
//
// TypeScript infers `(arr.match(re) || [])` as `RegExpMatchArray | never[]`,
// which makes `.includes(value)` require `never`. Widening includes to accept
// `unknown` is the standard project-level fix for this inference gap.
// ---------------------------------------------------------------------------
interface Array<T> {
  includes(searchElement: unknown, fromIndex?: number): boolean;
}

interface ReadonlyArray<T> {
  includes(searchElement: unknown, fromIndex?: number): boolean;
}
