import { useState, useEffect } from "react";
import { Card, Row, Col } from "antd";
import { Pie, Column, Line } from "@ant-design/charts";
import type { Statistics } from "@/types/dashboard";
import type { SecurityEvent } from "@/types/dashboard";
import { getSecurityEventStats } from "@/api/threat";
import styles from "./Charts.module.less";

interface ChartsProps {
  statistics: Statistics;
  securityData: SecurityEvent[];
}

const Charts: React.FC<ChartsProps> = ({ statistics, securityData }) => {
  // 类别名称映射
  const categoryNames: Record<string, string> = {
    config_security: "配置安全",
    skill_security: "Skill安全",
    command_violation: "危险命令",
    component_change: "组件变更",
    content_check: "上下文检查",
  };

  // 计算各类别的事件数量
  const categoryStats = securityData.reduce(
    (acc, item) => {
      const category = item.category || "unknown";
      acc[category] = (acc[category] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  // 饼图数据 - 类别分布
  const pieData = Object.keys(categoryStats).map((key) => ({
    type: categoryNames[key] || key,
    value: categoryStats[key],
  }));

  const pieConfig = {
    data: pieData,
    angleField: "value",
    colorField: "type",
    radius: 0.8,
    innerRadius: 0.4,
    label: {
      type: "inner",
      offset: "-50%",
      content: "{value}",
      style: {
        textAlign: "center",
        fontSize: 14,
      },
    },
    tooltip: {
      title: "type", // 标题
      items: ["value"], // 数据项
    },
    interactions: [
      {
        type: "element-active",
      },
      {
        type: "pie-statistic-active",
      },
    ],
    statistic: {
      title: {
        offsetY: -8,
        customContent: "总事件",
        style: { fontSize: "14px", color: "rgba(230,237,243,0.65)" },
      },
      content: {
        offsetY: 4,
        style: {
          fontSize: "20px",
          fontWeight: "bold",
          color: "rgba(230,237,243,0.85)",
        },
        customContent: `${statistics.total}`,
      },
    },
    color: ["#ff4d4f", "#faad14", "#52c41a", "#1890ff"],
    legend: {
      color: {
        title: false,
        position: "right",
        rowPadding: 5,
        itemLabelFill: "white",
      },
    },
  };

  // 柱状图数据 - 威胁级别分布
  const columnData = [
    {
      type: "严重",
      value: statistics.critical,
    },
    {
      type: "高危",
      value: statistics.high,
    },
    {
      type: "中危",
      value: statistics.medium,
    },
    {
      type: "低危",
      value: statistics.low,
    },
    {
      type: "日志",
      value: statistics.info,
    },
  ];
  const colors = ["#ff4d4f", "#ff7a45", "#faad14", "#52c41a", "#1890ff"];

  const columnConfig = {
    data: columnData,
    xField: "type",
    yField: "value",
    colorField: "type",
    color: colors,
    legend: {
      color: {
        position: "top",
        itemLabelFill: "#fff",
        layout: {
          justifyContent: "center", // 水平居中
        },
      },
    },
    columnWidthRatio: 0.8,
    marginRatio: 0,
    style: {
      maxWidth: 50,
      fill: ({ type }: { type: string }) => {
        const index = columnData.findIndex((item) => item.type === type);
        return colors[index];
      },
    },
    axis: {
      x: {
        line: true, // 是否显示轴线
        arrow: false, // 是否显示箭头
        lineStroke: "#fff",
        tickStroke: "#fff",
        labelFill: "#fff",
      },
      y: {
        line: true, // 是否显示轴线
        arrow: false, // 是否显示箭头
        lineStroke: "#fff",
        tickStroke: "#fff",
        labelFill: "#fff",
      },
    },
  };

  // 折线图数据 - 从接口获取
  const [lineData, setLineData] = useState<{ date: string; value: number }[]>(
    [],
  );

  useEffect(() => {
    const fetchLineData = async () => {
      try {
        const res = await getSecurityEventStats();
        const formatted = res.map((item) => ({
          date: item.date.substring(5), // 取 "MM-DD" 格式
          value: item.count,
        }));
        setLineData(formatted);
      } catch (error) {
        console.error("获取安全事件统计数据失败:", error);
      }
    };
    fetchLineData();
  }, []);

  const lineConfig = {
    data: lineData.map((d) => ({ ...d, type: "事件数" })),
    xField: "date",
    yField: "value",
    colorField: "type",
    color: ["#55a722"],
    smooth: true,
    point: {
      size: 5,
      shape: "diamond",
    },
    style: {
      lineWidth: 3,
    },
    areaStyle: {
      fill: "l(270) 0:rgba(13,17,23,0) 0.5:#55a722 1:#55a722",
      fillOpacity: 0.15,
    },
    tooltip: {
      showMarkers: true,
    },
    state: {
      active: {
        style: {
          shadowBlur: 4,
          stroke: "#000",
          fillOpacity: 1,
        },
      },
    },
    interactions: [
      {
        type: "marker-active",
      },
    ],
    legend: {
      color: {
        position: "top",
        itemLabelFill: "#fff",
        layout: {
          justifyContent: "center", // 水平居中
        },
      },
    },
    axis: {
      x: {
        line: true, // 是否显示轴线
        arrow: false, // 是否显示箭头
        lineStroke: "#fff",
        tickStroke: "#fff",
        labelFill: "#fff",
      },
      y: {
        line: true, // 是否显示轴线
        arrow: false, // 是否显示箭头
        lineStroke: "#fff",
        tickStroke: "#fff",
        labelFill: "#fff",
      },
    },
  };

  return (
    <Row gutter={16}>
      <Col span={8}>
        <Card
          headStyle={{
            minHeight: "48px",
          }}
          title={<span className={styles.cardTitle}>风险类型分布</span>}
        >
          <div className={styles.chartContainer}>
            <Pie {...pieConfig} height={280} />
          </div>
        </Card>
      </Col>
      <Col span={8}>
        <Card
          headStyle={{
            minHeight: "48px",
          }}
          title={<span className={styles.cardTitle}>威胁等级分布</span>}
        >
          <div className={styles.chartContainer}>
            <Column {...columnConfig} height={280} />
          </div>
        </Card>
      </Col>
      <Col span={8}>
        <Card
          headStyle={{
            minHeight: "48px",
          }}
          title={<span className={styles.cardTitle}>近7天趋势</span>}
        >
          {" "}
          <div className={styles.chartContainer}>
            <Line {...lineConfig} height={280} />{" "}
          </div>
        </Card>
      </Col>
    </Row>
  );
};

export default Charts;
