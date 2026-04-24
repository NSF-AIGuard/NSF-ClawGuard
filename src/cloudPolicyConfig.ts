import { getLogger } from "./logger.js";
import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";
import { openclawRoot, restartGateway } from "./utils.js";
import {
    dbGetLatestPolicyConfig,
    dbUpsertPolicyConfig,
    dbSaveDefaultModel,
    dbGetDefaultModel,
    type PolicyConfig,
} from "./database.js";
import { stopHeartbeatReporter } from "./api.js";

let openclawConfig: Record<string, unknown> | null = null;

export function setOpenclawConfig(config: Record<string, unknown>): void {
    openclawConfig = config;
}

interface OpenClawConfig {
    models?: {
        mode?: string;
        providers?: Record<string, {
            [key: string]: any;
            models?: Array<Record<string, any>>;
        }>;
    };
    agents?: {
        defaults?: {
            model?: {
                primary?: string;
                fallbacks?: string[];
            };
            models?: Record<string, unknown>;
            workspace?: string;
        };
    };
    [key: string]: any;
}

interface ILlmProxy {
    provider_id: string;
    compatibility: string;
    base_url: string;
    model_id: string;
    api_key: string | null;
}

interface IExtraCommandBlacklistItem {
    pattern: string;
    name: string;
    level: string;
}

export interface IPolicyResponseData {
    version: string;
    skill_check_enabled: boolean;
    command_check_enabled: boolean;
    config_check_enabled: boolean;
    block_on_violation: boolean;
    heartbeat_interval: number;
    extra_command_blacklist: IExtraCommandBlacklistItem[];
    skill_id_blacklist: string[];
    llm_mode: string | null;
    llm_proxy: ILlmProxy | null;
    onboard_command: string | null;
}

/** 当前策略配置 */
export let currentPolicyConfig: PolicyConfig | null = null;

/** 获取当前策略配置 */
export async function initPolicyConfig(): Promise<void> {
    const logger = getLogger();
    try {
        const config = await dbGetLatestPolicyConfig();
        if (config) {
            currentPolicyConfig = config;
        } else {
            const defaultConfig: PolicyConfig = {
                id: 0,
                policy_version: "",
                skill_check_enabled: true,
                command_check_enabled: true,
                config_check_enabled: true,
                block_on_violation: false,
                extra_command_blacklist: "",
                skill_id_blacklist: "",
                llm_mode: "",
                llm_proxy: "",
                onboard_command: "",
                updated_at: new Date().toISOString(),
                needSetLLM: false,
                previous_model: "",
                heartbeat_interval: 30,
            };
            currentPolicyConfig = defaultConfig;
        }
    } catch (error) {
        logger?.warn(`[PolicyConfig] 获取策略配置失败: ${error}`);
        const defaultConfig: PolicyConfig = {
            id: 0,
            policy_version: "",
            skill_check_enabled: true,
            command_check_enabled: true,
            config_check_enabled: true,
            block_on_violation: false,
            extra_command_blacklist: "",
            skill_id_blacklist: "",
            llm_mode: "",
            llm_proxy: "",
            onboard_command: "",
            updated_at: new Date().toISOString(),
            needSetLLM: false,
            previous_model: "",
            heartbeat_interval: 30,
        };
        currentPolicyConfig = defaultConfig;
    }


    // if (currentPolicyConfig?.llm_mode !== "proxy") {
    //     return
    // }

    // const llmProxyConfig = JSON.parse(currentPolicyConfig?.llm_proxy)
    // if (currentPolicyConfig?.needSetLLM && currentPolicyConfig?.previous_model !== "") {
    //     await dbUpdateNeedSetLLM(false, currentPolicyConfig.id)
    //     await resetOpenclawPrimaryModel({ "provider_id": llmProxyConfig?.provider_id!, "model_id": llmProxyConfig?.model_id! })
    //     const [providerId, modelId] = currentPolicyConfig?.previous_model.split("/");
    //     let delCustomProxy: ILlmProxy = { "provider_id": providerId, "compatibility": "", "base_url": "", model_id: modelId, "api_key": "" };
    //     removeCustomModelProxyFromConfig(delCustomProxy);
    // }
}

export async function updateLLMConfigAndSaveConfig(currentConfig: PolicyConfig | null, newPolicyConfig: IPolicyResponseData): Promise<boolean> {
    const logger = getLogger();
    const currentLlmMode = currentConfig?.llm_mode || "";
    const newLlmMode = newPolicyConfig.llm_mode || "";

    const currentLlmProxy = currentConfig?.llm_proxy || "";
    // const newLlmProxy = newPolicyConfig.llm_proxy ? JSON.stringify(newPolicyConfig.llm_proxy) : "";

    logger?.info(`currentLlmMode:${currentLlmMode}`)
    logger?.info(`newLlmMode:${newLlmMode}`)

    if (!currentLlmMode || currentLlmMode === "") {
        if (newLlmMode === "sdk") {
            await response2ConfigAndSave(newPolicyConfig, false, "");
            logger?.info(`[LLMConfig] 当前配置为空，新配置为 sdk，直接返回`);
            return true
        }
        if (newLlmMode === "proxy") {
            logger?.info(`[LLMConfig] 当前配置为空，新配置为 proxy，获取当前默认模型并保存`);
            const defaultModel = await getOpenclawDefaultModel();
            if (defaultModel) {
                await dbSaveDefaultModel(defaultModel);
                logger?.info(`[LLMConfig] 已保存默认模型: ${defaultModel.provider_id}/${defaultModel.model_id}`);
            } else {
                logger?.warn(`[LLMConfig] 无法获取当前默认模型`);
            }

            await response2ConfigAndSave(newPolicyConfig, false, "");
            logger?.info(`执行 onboard_command`);
            try {
                execSync(newPolicyConfig.onboard_command!)
            } catch (error) {
                logger?.warn(`[LLMConfig] 执行 onboard_command 失败，但这可能只是系统正常报错: ${error}`);
            }
            resetOpenclawPrimaryModel({ "provider_id": newPolicyConfig.llm_proxy?.provider_id!, "model_id": newPolicyConfig.llm_proxy?.model_id! })
            logger?.info(`[LLMConfig] 已设置默认模型: ${newPolicyConfig.llm_proxy?.provider_id}/${newPolicyConfig.llm_proxy?.model_id}`);

            restartGateway()
            return false
        }
    }

    if (currentLlmMode === "sdk") {
        if (newLlmMode === "sdk") {
            await response2ConfigAndSave(newPolicyConfig, false, "");
            logger?.info(`[LLMConfig] 当前 sdk，新配置为 sdk，直接返回`);
            return true
        }
        if (newLlmMode === "proxy") {
            logger?.info(`[LLMConfig] 当前 sdk，新配置为 proxy，获取当前默认模型并保存`);
            stopHeartbeatReporter();
            const defaultModel = await getOpenclawDefaultModel();
            if (defaultModel) {
                await dbSaveDefaultModel(defaultModel);
                logger?.info(`[LLMConfig] 已保存默认模型: ${defaultModel.provider_id}/${defaultModel.model_id}`);
            } else {
                logger?.warn(`[LLMConfig] 无法获取当前默认模型`);
            }
            await response2ConfigAndSave(newPolicyConfig, false, "");
            try {
                logger?.info(`执行 onboard_command`);
                execSync(newPolicyConfig.onboard_command!)
            } catch (error) {
                logger?.warn(`[LLMConfig] 执行 onboard_command 失败，但这可能只是系统正常报错: ${error}`);
            }

            await resetOpenclawPrimaryModel({ "provider_id": newPolicyConfig.llm_proxy?.provider_id!, "model_id": newPolicyConfig.llm_proxy?.model_id! })

            logger?.info(`[LLMConfig] 已设置默认模型: ${newPolicyConfig.llm_proxy?.provider_id!}/${newPolicyConfig.llm_proxy?.model_id!}`);

            restartGateway()
            return false

        }
    }

    if (currentLlmMode === "proxy") {
        if (newLlmMode === "sdk") {
            logger?.info(`[LLMConfig] 当前 proxy，新配置为 sdk，获取保存的默认模型并恢复`);
            stopHeartbeatReporter();
            const defaultModel = await dbGetDefaultModel();
            let currentCustomProxy: ILlmProxy | null = null;
            if (currentLlmProxy) {
                try {
                    currentCustomProxy = JSON.parse(currentLlmProxy) as ILlmProxy;
                } catch {
                    currentCustomProxy = null;
                }
            }
            await response2ConfigAndSave(newPolicyConfig, false, "");
            if (defaultModel) {
                logger?.info(`[LLMConfig] 恢复默认模型: ${defaultModel.provider_id}/${defaultModel.model_id}`);

                await resetOpenclawPrimaryModel(defaultModel)
            } else {
                logger?.warn(`[LLMConfig] 未找到保存的默认模型，无法恢复`);
            }
            await removeCustomModelProxyFromConfig(currentCustomProxy);
            logger?.info(`[LLMConfig] 已移除自定义模型: ${currentCustomProxy?.provider_id}/${currentCustomProxy?.model_id}`);

            restartGateway()
            return false
        }
        if (newLlmMode === "proxy") {
            logger?.info(`[LLMConfig] 当前 proxy，新配置为 proxy 但配置变化或强制变更`);
            stopHeartbeatReporter();
            const defaultModel = await dbGetDefaultModel();
            let currentCustomProxy: ILlmProxy | null = null;
            if (currentLlmProxy) {
                try {
                    currentCustomProxy = JSON.parse(currentLlmProxy) as ILlmProxy;
                } catch {
                    currentCustomProxy = null;
                }
            }

            await response2ConfigAndSave(newPolicyConfig, false, "");
            if (defaultModel) {
                logger?.info(`[LLMConfig] 恢复默认模型: ${defaultModel.provider_id}/${defaultModel.model_id}`);
                await resetOpenclawPrimaryModel(defaultModel)
            } else {
                logger?.warn(`[LLMConfig] 未找到保存的默认模型，无法恢复`);
            }

            await removeCustomModelProxyFromConfig(currentCustomProxy);
            logger?.info(`[LLMConfig] 已移除自定义模型: ${currentCustomProxy?.provider_id}/${currentCustomProxy?.model_id}`);


            try {
                logger?.info(`执行 onboard_command`);
                execSync(newPolicyConfig.onboard_command!)
            } catch (error) {
                logger?.warn(`[LLMConfig] 执行 onboard_command 失败，但这可能只是openclaw 添加模型时的正常报错: ${error}`);
            }
            await resetOpenclawPrimaryModel({ "provider_id": newPolicyConfig.llm_proxy?.provider_id!, "model_id": newPolicyConfig.llm_proxy?.model_id! })
            logger?.info(`[LLMConfig] 已设置默认模型: ${newPolicyConfig.llm_proxy?.provider_id}/${newPolicyConfig.llm_proxy?.model_id}`);

            restartGateway()
            return false
        }
    }
    return true
}

async function getOpenclawDefaultModel(): Promise<{ provider_id: string; model_id: string } | null> {
    // const logger = getLogger();

    const config = openclawConfig;
    const primaryModel = (config as any)?.agents?.defaults?.model?.primary;
    if (primaryModel && typeof primaryModel === "string" && primaryModel.includes("/")) {
        const [providerId, modelId] = primaryModel.split("/");

        if (providerId && modelId) {
            return {
                provider_id: providerId,
                model_id: modelId,
            };
        }
    }

    return null;

}

export function updateCurrentPolicyConfig(newPolicyConfig: PolicyConfig | null = null) {
    currentPolicyConfig = newPolicyConfig;
}

export async function response2ConfigAndSave(policyData: IPolicyResponseData, needSetLLM: boolean, previousModel: string): Promise<void> {
    const configToSave = {
        policy_version: policyData.version,
        skill_check_enabled: policyData.skill_check_enabled,
        command_check_enabled: policyData.command_check_enabled,
        config_check_enabled: policyData.config_check_enabled,
        block_on_violation: policyData.block_on_violation,
        extra_command_blacklist: JSON.stringify(policyData.extra_command_blacklist),
        skill_id_blacklist: JSON.stringify(policyData.skill_id_blacklist),
        llm_mode: policyData.llm_mode || "",
        llm_proxy: policyData.llm_proxy ? JSON.stringify(policyData.llm_proxy) : "",
        onboard_command: policyData.onboard_command || "",
        updated_at: new Date().toISOString(),
        needSetLLM: needSetLLM,
        previous_model: previousModel,
        heartbeat_interval: policyData.heartbeat_interval || 30,
    };

    await dbUpsertPolicyConfig(configToSave);
}


function resetOpenclawPrimaryModel(Model: { provider_id: string; model_id: string }) {
    const changeOpenclawDefaultModelCmd = `openclaw models set ${Model.provider_id}/${Model.model_id}`;
    execSync(changeOpenclawDefaultModelCmd)
}

async function removeCustomModelProxyFromConfig(currentCustomProxy: ILlmProxy | null): Promise<void> {
    const logger = getLogger();

    const providerId = currentCustomProxy?.provider_id || "";
    const modelId = currentCustomProxy?.model_id || "";
    try {
        const openclawRootPath = openclawRoot();
        const configPath = path.join(openclawRootPath, "openclaw.json");

        if (!fs.existsSync(configPath)) {
            logger?.error("配置文件不存在: ${configPath}")
            return
        }

        const configContent = fs.readFileSync(configPath, "utf-8");
        const config: OpenClawConfig = JSON.parse(configContent);

        let hasChanges = false;

        if (config.models?.providers?.[providerId]) {
            const provider = config.models.providers[providerId];

            if (provider.models && Array.isArray(provider.models)) {
                const modelIndex = provider.models.findIndex((m) => m.id === modelId);
                if (modelIndex !== -1) {
                    provider.models.splice(modelIndex, 1);
                    hasChanges = true;
                }
            }

            if (provider.models && provider.models.length === 0) {
                delete config.models.providers[providerId];
                hasChanges = true;
            }
        }

        if (config.agents?.defaults?.model?.primary === `${providerId}/${modelId}`) {
            config.agents.defaults.model.primary = "";
            hasChanges = true;
        }

        if (config.agents?.defaults?.model?.fallbacks) {
            const fallbackIndex = config.agents.defaults.model.fallbacks.indexOf(
                `${providerId}/${modelId}`
            );
            if (fallbackIndex !== -1) {
                config.agents.defaults.model.fallbacks.splice(fallbackIndex, 1);
                hasChanges = true;
            }
        }

        if (config.agents?.defaults?.models?.[`${providerId}/${modelId}`]) {
            delete config.agents.defaults.models[`${providerId}/${modelId}`];
            hasChanges = true;
        }

        if (hasChanges) {
            const updatedContent = JSON.stringify(config, null, 2);
            fs.writeFileSync(configPath, updatedContent, "utf-8");
            logger?.info(`成功从配置中删除模型 ${providerId}/${modelId}`);
            return
        } else {
            logger?.error(`未找到模型 ${providerId}/${modelId} 在配置中`);
            return
        }
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger?.error(`删除模型配置${providerId}/${modelId}失败   ${errorMessage}`);
        return
    }
}
