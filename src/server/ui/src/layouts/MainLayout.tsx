import { useState, useEffect } from "react";
import { Outlet, useNavigate, useLocation } from "react-router-dom";
import { Layout, Tooltip, Menu } from "antd";
import {
  UserOutlined,
  InfoCircleOutlined,
} from "@ant-design/icons";
import { useSelector } from "react-redux";
import { RootState } from "@/store";
import logo from "@/assets/logo.png";
import styles from "./MainLayout.module.less";

const { Header, Content } = Layout;

const MainLayout = () => {
  const [collapsed] = useState(false);
  const [sidebarWidth, setSidebarWidth] = useState(0); // 默认展开宽度
  const [currentTime, setCurrentTime] = useState(new Date());
  const navigate = useNavigate();
  const location = useLocation();

  const sidebarCollapsed = useSelector(
    (state: RootState) => state.app.sidebarCollapsed,
  );

  // 监听折叠状态变化，动态设置侧边栏宽度
  useEffect(() => {
    const isCollapsed = collapsed || sidebarCollapsed;
    setSidebarWidth(isCollapsed ? 64 : 0); // 折叠时64px，展开时200px
  }, [collapsed, sidebarCollapsed]);

  // 设置实时时间更新
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);

    return () => {
      clearInterval(timer);
    };
  }, []);

  const menuItems = [
    {
      key: "/dashboard",
      path: "/dashboard",
      label: "事件概览",
    },
    {
      key: "/audit-log",
      path: "/audit-log",
      label: "安全审计",
    }
  ];

  const handleMenuClick = ({ key }: { key: string }) => {
    navigate(key);
  };

  return (
    <Layout className={styles.mainLayout}>
      <Header className={styles.mainLayoutHeader}>
        <div className={styles.mainLayoutHeaderLeft}>
          <img
            src={logo}
            alt="Logo"
            className={styles.mainLayoutHeaderLogoImage}
          />
          <span className={styles.mainLayoutHeaderTitle}>绿盟Openclaw端侧安全防护平台</span>
          <Menu
            theme="light"
            mode="horizontal"
            selectedKeys={[location.pathname]}
            items={menuItems}
            onClick={handleMenuClick}
            className={styles.mainLayoutHeaderMenu}
          />
        </div>
        <div className={styles.mainLayoutHeaderRight}>
          <div className={styles.mainLayoutHeaderDate}>
            {currentTime.toLocaleString()}
          </div>
          <Tooltip title="关于">
            <InfoCircleOutlined className={styles.mainLayoutHeaderInfoIcon} />
          </Tooltip>
          <div className={styles.mainLayoutHeaderUser}>
            <UserOutlined />
            <span>Admin</span>
          </div>
        </div>
      </Header>
      <Layout
        className={styles.mainLayoutBody}
        style={{ marginLeft: sidebarWidth }}
      >
        <Content className={styles.mainLayoutContent}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  );
};

export default MainLayout;
