import type { Command } from "commander";
import type { IncomingMessage, ServerResponse } from "node:http";


export interface IInputMsgData {
  stage: "input";
  question: string;
  flowDetect: 0 | 1 | 2;
}

export interface IResponseBody<T = unknown> {
  data: T;
  errCode: number;
  errMsg: string;
}

export interface IOutputMsgData {
  stage: "output";
  output: string;
  flowDetect: 0 | 1 | 2;
}
export interface Logger {
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
  debug(message: string): void;
}

export type PluginLogger = Logger

export interface PluginConfig {
  [key: string]: any;
}

export interface Message {
  role: string;
  content: string;
  sender?: {
    id: string;
    [key: string]: any;
  };
  [key: string]: any;
}

export interface EventContext {
  sessionKey?: string;
  sendMessage?: (message: Message) => Promise<void>;
  terminateSession?: (options: {
    reason: string;
    silent: boolean;
  }) => Promise<void>;
  [key: string]: any;
}

export interface ToolCallEvent {
  toolName: string;
  params: Record<string, any>;
}

export interface AgentStartEvent {
  input: string; // Assuming input is a string or object with input
  [key: string]: any;
}

export interface AgentEndEvent {
  output: string; // Assuming output is a string or object with output
  [key: string]: any;
}

export interface PatternRule {
  type: string;
  regex: RegExp;
}

export type OpenClawPluginCliContext = {
  program: Command;
  config?: {
    [key: string]: any;
  };
  workspaceDir?: string;
  logger: Logger;
};

type OpenClawPluginCliRegistrar = (
  ctx: OpenClawPluginCliContext,
) => void | Promise<void>;

export type OpenClawPluginHttpRouteAuth = "gateway" | "plugin";
export type OpenClawPluginHttpRouteMatch = "exact" | "prefix";

export type OpenClawPluginHttpRouteHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  logger: Logger
) => Promise<boolean | void> | boolean | void;

export type OpenClawPluginHttpRouteParams = {
  path: string;
  handler: OpenClawPluginHttpRouteHandler;
  auth: OpenClawPluginHttpRouteAuth;
  match?: OpenClawPluginHttpRouteMatch;
  replaceExisting?: boolean;
};

export type PluginHookLlmOutputEvent = {
  runId: string;
  sessionId: string;
  provider: string;
  model: string;
  assistantTexts: string[];
  lastAssistant?: unknown;
  usage?: {
    input?: number;
    output?: number;
    cacheRead?: number;
    cacheWrite?: number;
    total?: number;
  };
};
export type PluginHookAgentContext = {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  workspaceDir?: string;
  messageProvider?: string;
  /** What initiated this agent run: "user", "heartbeat", "cron", or "memory". */
  trigger?: string;
  /** Channel identifier (e.g. "telegram", "discord", "whatsapp"). */
  channelId?: string;
};
export interface OpenClawPluginApi {
  logger: Logger;
  config: PluginConfig;
  pluginConfig: PluginConfig;
  resolvePath: (input: string) => string;
  version: string;
  registerHttpRoute: (params: OpenClawPluginHttpRouteParams) => void;
  registerCli: (
    registrar: OpenClawPluginCliRegistrar,
    opts?: { commands?: string[] },
  ) => void;
  on(
    event: string,
    handler: (
      event: any,
      ctx: EventContext,
    ) => Promise<void | { block: boolean; blockReason: string }>,
  ): void;
}
