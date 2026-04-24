import { useState, useCallback } from "react";
import { Modal, Form, Input, message } from "antd";
import { getConfig, saveConfig } from "@/api/config";
import type { CloudConfig } from "@/api/config";
import styles from "./MainLayout.module.less";

interface CloudConfigModalProps {
  open: boolean;
  onClose: () => void;
}

const CloudConfigModal: React.FC<CloudConfigModalProps> = ({
  open,
  onClose,
}) => {
  const [confirmLoading, setConfirmLoading] = useState(false);
  const [form] = Form.useForm<CloudConfig>();

  // 打开时加载配置
  const handleAfterOpenChange = useCallback(
    (visible: boolean) => {
      if (visible) {
        getConfig()
          .then((data) => {
            if (data) {
              form.setFieldsValue(data);
            }
          })
          .catch(() => {
            // 获取配置失败时不做处理，用户可以重新填写
          });
      }
    },
    [form],
  );

  // 关闭
  const handleClose = useCallback(() => {
    form.resetFields();
    onClose();
  }, [form, onClose]);

  // 提交
  const handleSubmit = useCallback(async () => {
    try {
      const values = await form.validateFields();
      setConfirmLoading(true);
      await saveConfig(values);
      message.success("云端配置保存成功,正在重启网关生效");
      handleClose();
    } catch {
      // 表单校验失败或接口请求失败，不关闭模态框
    } finally {
      setConfirmLoading(false);
    }
  }, [form, handleClose]);

  return (
    <Modal
      title="云端接入配置"
      className={styles.cloudModal}
      open={open}
      onOk={handleSubmit}
      onCancel={handleClose}
      afterOpenChange={handleAfterOpenChange}
      confirmLoading={confirmLoading}
      okText="确定"
      cancelText="取消"
      centered
      destroyOnClose
      width={520}
    >
      <Form form={form} layout="vertical" className={styles.cloudForm}>
        <Form.Item
          name="baseUrl"
          label="Base URL"
          rules={[
            { required: true, message: "请输入 Base URL" },
            {
              validator: (_: any, value: string) => {
                if (!value) return Promise.resolve();
                const urlPattern = /^https?:\/\/(.+):(\d+)$/;
                const match = value.match(urlPattern);
                if (!match) {
                  return Promise.reject(
                    new Error(
                      "请输入正确的格式，如 http://example.com:8080 或 http://192.168.1.1:3000",
                    ),
                  );
                }
                const port = parseInt(match[2], 10);
                if (port < 1 || port > 65535) {
                  return Promise.reject(new Error("端口号范围为 1-65535"));
                }
                return Promise.resolve();
              },
            },
          ]}
        >
          <Input placeholder="如：http://example.com:8080" />
        </Form.Item>
        <Form.Item
          name="accessKey"
          label="Access Key"
          rules={[{ required: true, message: "请输入 Access Key" }]}
        >
          <Input placeholder="请输入 Access Key" />
        </Form.Item>
        <Form.Item
          name="secretKey"
          label="Secret Key"
          rules={[{ required: true, message: "请输入 Secret Key" }]}
        >
          <Input.Password placeholder="请输入 Secret Key" />
        </Form.Item>
        <Form.Item
          name="appId"
          label="App ID"
          rules={[{ required: true, message: "请输入 App ID" }]}
        >
          <Input placeholder="请输入 App ID" />
        </Form.Item>
      </Form>
    </Modal>
  );
};

export default CloudConfigModal;