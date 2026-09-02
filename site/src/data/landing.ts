export type LandingLocale = 'en' | 'ru' | 'zh-cn';

type Action = {
  label: string;
  url: string;
};

type Protocol = {
  name: string;
  role: string;
  notes: string;
};

type UseCase = {
  title: string;
  summary: string;
  commandHint: string;
  category: string;
};

export type LandingCopy = {
  localeLabel: string;
  htmlLang: string;
  title: string;
  description: string;
  skipToContent: string;
  nav: {
    home: string;
    docs: string;
    bot: string;
    cookbook: string;
    useCases: string;
  };
  hero: {
    kicker: string;
    title: string;
    text: string;
    actions: Action[];
  };
  architecture: {
    id: string;
    heading: string;
    text: string;
    steps: string[];
  };
  protocols: {
    id: string;
    heading: string;
    items: Protocol[];
  };
  safety: {
    id: string;
    heading: string;
    text: string;
    checks: string[];
  };
  useCases: {
    id: string;
    heading: string;
    items: UseCase[];
  };
  bot: {
    id: string;
    heading: string;
    intro: string;
    steps: string[];
  };
  cookbook: {
    id: string;
    heading: string;
    intro: string;
    links: {
      title: string;
      description: string;
      url: string;
    }[];
  };
  finalCta: {
    id: string;
    heading: string;
    text: string;
    actions: Action[];
  };
};

export const landingData: Record<LandingLocale, LandingCopy> = {
  en: {
    localeLabel: 'English',
    htmlLang: 'en',
    title: 'VPN Hub',
    description: 'Route your devices and private destinations through exactly one selected path.',
    skipToContent: 'Skip to main content',
    nav: {
      home: 'Home',
      docs: 'Docs',
      bot: 'Telegram bot',
      cookbook: 'Cookbook',
      useCases: 'Use cases',
    },
    hero: {
      kicker: 'Routed VPN control plane',
      title: 'One connection. Every network. No silent fallback.',
      text: 'Route each device and private destination through the egress you choose. If traffic leaves its expected path, fail closed instead of quietly switching to direct internet.',
      actions: [
        { label: 'Deploy your hub', url: '/vpn-hub/docs/start/install/' },
        { label: 'View on GitHub', url: 'https://github.com/rekurt/vpn-hub' },
      ],
    },
    architecture: {
      id: 'architecture',
      heading: 'How routing is built',
      text: 'A single desired state file drives reconciliation. Hubctl stores comments, the agent applies rules, and a single gate serializes all network changes.',
      steps: [
        'policy file defines devices, tunnels, egress role, and DNS scope',
        'agent renders namespaces, nftables chains, nft set, and service units from that policy',
        'all outbound traffic enters namespace-aware policy checks before leaving the host',
      ],
    },
    protocols: {
      id: 'protocols',
      heading: 'Supported egress and entry paths',
      items: [
        { name: 'Direct egress', role: 'Emergency path', notes: 'Direct path is explicit and guarded by policy. It is not an automatic fallback.' },
        { name: 'WireGuard', role: 'Primary tunnel', notes: 'One tunnel, one namespace, deterministic policy scope.' },
        { name: 'AmneziaWG', role: 'Client entry', notes: 'Obfuscation settings are part of tunnel profile rotation.' },
        { name: 'Xray / VLESS', role: 'Alternative transport', notes: 'Per-tunnel namespace and explicit profile handling.' },
        { name: 'OpenVPN', role: 'Provider compatibility', notes: 'Kept for mixed provider environments.' },
      ],
    },
    safety: {
      id: 'safety',
      heading: 'Operational safety model',
      text: 'Design goal: explicit routing and measurable drift recovery.',
      checks: [
        'Root-only operations for install, uninstall, and state mutation.',
        'No silent fallback to direct outbound traffic when policy becomes invalid.',
        'Provider input is validated and normalized before state reconciliation.',
        'Telegram profiles keep only short-lived profile keys and no host private keys.',
        'SSH recovery runbooks are documented and tested with dry-run and confirm windows.',
      ],
    },
    useCases: {
      id: 'use-cases',
      heading: 'Use cases covered by this project',
      items: [
        { title: 'Split tunnel by destination', category: 'Routing', summary: 'Keep corp, private, and public traffic separate with per-tunnel DNS and namespace policy.', commandHint: 'hubctl tunnel routes corp-private --add 203.0.113.0/24' },
        { title: 'Home office through private provider', category: 'Connectivity', summary: 'Send all employee devices through a single selected egress with quick egress swap.', commandHint: 'hubctl device set-egress laptop corp-egress' },
        { title: 'Private service access', category: 'Security', summary: 'Expose private subnets only through approved tunnels with DNS pinning.', commandHint: 'hubctl tunnel routes corp-private --add 192.0.2.0/24' },
        { title: 'SOCKS5 app steering', category: 'Operations', summary: 'Send selected application traffic through an assigned tunnel without changing whole host routing.', commandHint: 'hubctl routes' },
        { title: 'Provider migration with rollback', category: 'Availability', summary: 'Test canary candidates, then restore the last-known-good upstream if health fails.', commandHint: 'hubctl subscription refresh corp-egress' },
        { title: 'Device isolation', category: 'Security', summary: 'Reject unplanned client-to-client traffic by default and add explicit ACLs.', commandHint: 'hubctl client-acl add phone laptop tcp/22' },
        { title: 'Incident pause and rollback', category: 'Reliability', summary: 'Stop risky changes and restore previous revision through timer-based confirmation.', commandHint: 'hubctl deploy --confirm-within 5m' },
        { title: 'Private DNS and DNS zone split', category: 'Networking', summary: 'Private names follow tunnel DNS policy, public names keep normal resolver behavior.', commandHint: 'hubctl tunnel zones corp-net --add corp.example' },
        { title: 'Emergency maintenance mode', category: 'Ops', summary: 'Disable one tunnel without dropping access by forcing a planned migration path.', commandHint: 'hubctl tunnel disable corp-egress' },
        { title: 'Fleet onboarding and profile rotation', category: 'Lifecycle', summary: 'Issue deterministic client profiles with revision-aware identifiers.', commandHint: 'hubctl device add laptop --egress corp-egress --address 198.51.100.10/32' },
        { title: 'Drift correction', category: 'Compliance', summary: 'Validate declared state, then re-apply controlled policy when runtime state diverges.', commandHint: 'hubctl validate && hubctl deploy' },
        { title: 'Read-only health for operators', category: 'Monitoring', summary: 'Track health, drift, and unit status before applying production changes.', commandHint: 'hubctl status --format yaml' },
      ],
    },
    bot: {
      id: 'bot-management',
      heading: 'Telegram bot operations examples',
      intro: 'The bot surfaces operational previews and confirmations, including guarded deploy flow and quick troubleshooting links.',
      steps: [
        'Review current revision and pending drift from a single status screen.',
        'Inspect candidate tunnel changes and approve via a one-minute countdown.',
        'Revoke or reissue device profiles from chat without touching SSH.',
        'Run subscription refresh and review canary health before promotion.',
      ],
    },
    cookbook: {
      id: 'cookbook',
      heading: 'Cookbook preview',
      intro: 'Runbooks are practical and reproducible.',
      links: [
        { title: 'Deploy with rollback window', description: 'Safe apply path with operator confirmation timeout.', url: '/vpn-hub/docs/cookbook/rolling-deploy/' },
        { title: 'Recovery and rollback', description: 'What to do when DNS, tunnel, or host state diverges.', url: '/vpn-hub/docs/cookbook/rollback-runbook/' },
        { title: 'Zero-trust segmentation', description: 'Build isolated app and private subnet policies from one hub file.', url: '/vpn-hub/docs/cookbook/segmentation/' },
        { title: 'Subscription canary testing', description: 'Promotion flow for candidate upstream endpoints.', url: '/vpn-hub/docs/cookbook/subscription-canary/' },
      ],
    },
    finalCta: {
      id: 'next-steps',
      heading: 'Ready to operate your hub safely?',
      text: 'Start with one controlled hub config and expand in small, verifiable steps.',
      actions: [
        { label: 'Read full docs', url: '/vpn-hub/docs/' },
        { label: 'Try safe deploy sequence', url: '/vpn-hub/docs/cookbook/rolling-deploy/' },
      ],
    },
  },
  ru: {
    localeLabel: 'Русский',
    htmlLang: 'ru',
    title: 'VPN Hub',
    description: 'Управление маршрутизацией сети через один выбранный путь без скрытого fallback.',
    skipToContent: 'Перейти к основному содержимому',
    nav: {
      home: 'Главная',
      docs: 'Документация',
      bot: 'Бот',
      cookbook: 'Cookbook',
      useCases: 'Сценарии',
    },
    hero: {
      kicker: 'Control plane роутинга VPN',
      title: 'Одно подключение. Любые сети. Никакого скрытого fallback.',
      text: 'Определяйте, через какой egress идёт каждый трафик устройства и приватный диапазон, и закрывайте путь если политика не выполняется.',
      actions: [
        { label: 'Развернуть хаб', url: '/vpn-hub/ru/docs/start/install/' },
        { label: 'Открыть GitHub', url: 'https://github.com/rekurt/vpn-hub' },
      ],
    },
    architecture: {
      id: 'architecture',
      heading: 'Как устроена маршрутизация',
      text: 'Единое состояние формирует план. Hubctl хранит комментарии, агент применяет правила и применяет один последовательный gate на все изменения сети.',
      steps: [
        'файл политики задаёт устройства, туннели, роль egress и зоны DNS',
        'агент строит namespaces, цепочки nftables и отпечаток ruleset из этой политики',
        'весь исходящий трафик проходит через namespace-aware policy, прежде чем выйти из хоста',
      ],
    },
    protocols: {
      id: 'protocols',
      heading: 'Поддерживаемые протоколы',
      items: [
        { name: 'Direct egress', role: 'Резервный путь', notes: 'Выключается только как явно настроенный сценарий, без автофолбэка.' },
        { name: 'WireGuard', role: 'Основной туннель', notes: 'Один туннель, одно пространство имён, детерминированная политика.' },
        { name: 'AmneziaWG', role: 'Точка входа клиентов', notes: 'Параметры обфускации обновляются вместе с ротацией профилей.' },
        { name: 'Xray / VLESS', role: 'Альтернативный транспорт', notes: 'Отдельные namespaces и явное управление профилями.' },
        { name: 'OpenVPN', role: 'Совместимость с провайдером', notes: 'Для смешанных инфраструктур и миграций.' },
      ],
    },
    safety: {
      id: 'safety',
      heading: 'Модель безопасности',
      text: 'Цель: явная маршрутизация и контролируемое восстановление состояния.',
      checks: [
        'Операции установки и изменения выполняются только от root.',
        'Нет скрытого перехода на прямой выход без политического согласования.',
        'Входные данные провайдера проходят валидацию перед пересборкой состояния.',
        'Telegram-профили содержат только публичные части и короткоживущие ключи сеанса.',
        'Для восстановления сохранены SSH-процедуры с режимом dry-run и подтверждения.',
      ],
    },
    useCases: {
      id: 'use-cases',
      heading: 'Завершённые сценарии',
      items: [
        { title: 'Раздельная маршрутизация', category: 'Сеть', summary: 'Отдельные пути для рабочей сети, частных адресов и общего интернета.', commandHint: 'hubctl tunnel routes corp-private --add 203.0.113.0/24' },
        { title: 'Домашний офис через private провайдер', category: 'Связность', summary: 'Все устройства сотрудников идут через выбранный egress, меняется в один шаг.', commandHint: 'hubctl device set-egress laptop corp-egress' },
        { title: 'Доступ к приватным сервисам', category: 'Безопасность', summary: 'Частные зоны DNS доступны только через согласованный tunnel.', commandHint: 'hubctl tunnel routes corp-private --add 192.0.2.0/24' },
        { title: 'Приложения через SOCKS5', category: 'Операции', summary: 'Изолированная маршрутизация только для выбранного приложения.', commandHint: 'hubctl routes' },
        { title: 'Миграция провайдера с откатом', category: 'Доступность', summary: 'Кандидатный upstream проходит canary; при проблеме возвращается last-known-good.', commandHint: 'hubctl subscription refresh corp-egress' },
        { title: 'Изоляция устройств', category: 'Безопасность', summary: 'По умолчанию нет device-to-device доступа, только явно разрешённые ACL.', commandHint: 'hubctl client-acl add phone laptop tcp/22' },
        { title: 'Инцидент и rollback', category: 'Надежность', summary: 'Откат по таймеру при рисковых изменениях.', commandHint: 'hubctl deploy --confirm-within 5m' },
        { title: 'Private DNS', category: 'Сеть', summary: 'Частные зоны работают в привязанном tunnel, публичные без перехвата.', commandHint: 'hubctl tunnel zones corp-net --add corp.example' },
        { title: 'Плановое отключение туннеля', category: 'Операции', summary: 'Выключение одного egress планируется с учетом зависимых устройств.', commandHint: 'hubctl tunnel disable corp-egress' },
        { title: 'Ввод новых устройств', category: 'Жизненный цикл', summary: 'Профили выдаются с версионированием и проверкой доступных адресов.', commandHint: 'hubctl device add laptop --egress corp-egress --address 198.51.100.10/32' },
        { title: 'Проверка дрейфа', category: 'Контроль', summary: 'Валидация декларативного плана и контролируемое восстановление состояния.', commandHint: 'hubctl validate && hubctl deploy' },
        { title: 'Наблюдаемость', category: 'Мониторинг', summary: 'Видно health, состояние юнитов и pending-очереди перед применением.', commandHint: 'hubctl status --format yaml' },
      ],
    },
    bot: {
      id: 'bot-management',
      heading: 'Управление через Telegram',
      intro: 'Бот показывает превью изменений, подтверждение с rollback-защитой и быстрое управление устройствами.',
      steps: [
        'Проверьте текущую ревизию и состояние drif/host из карточки статуса.',
        'Откройте превью изменений и подтвердите deploy с защитой от тишины.',
        'Отзыв/перевыпуск профиля выполняется из бота без SSH и с аудитом операций.',
        'Обновляйте подписки и смотрите canary-результат до применения в production.',
      ],
    },
    cookbook: {
      id: 'cookbook',
      heading: 'Актуальные сценарии',
      intro: 'Практические playbook для типовых задач по этапам.',
      links: [
        { title: 'Deploy с окном отката', description: 'Безопасный путь применения изменений.', url: '/vpn-hub/ru/docs/cookbook/rolling-deploy/' },
        { title: 'Восстановление и откат', description: 'Действия при дрейфе правил или health деградации.', url: '/vpn-hub/ru/docs/cookbook/rollback-runbook/' },
        { title: 'Сегментация без префиксов', description: 'Организация изолированных подсетей и ACL.', url: '/vpn-hub/ru/docs/cookbook/segmentation/' },
        { title: 'Canary для подписок', description: 'Контролируемая проверка кандидатов провайдеров.', url: '/vpn-hub/ru/docs/cookbook/subscription-canary/' },
      ],
    },
    finalCta: {
      id: 'next-steps',
      heading: 'Готовы начать работу?',
      text: 'Начните с одного контролируемого конфигурационного файла и добавляйте сценарии по очереди.',
      actions: [
        { label: 'Читать документацию', url: '/vpn-hub/ru/docs/' },
        { label: 'Пошаговый сценарий', url: '/vpn-hub/ru/docs/cookbook/rolling-deploy/' },
      ],
    },
  },
  'zh-cn': {
    localeLabel: '简体中文',
    htmlLang: 'zh-CN',
    title: 'VPN Hub',
    description: '通过单一指定路径对每台设备和私有网段进行路由，严格避免静默兜底。',
    skipToContent: '跳到主要内容',
    nav: {
      home: '首页',
      docs: '文档',
      bot: 'Telegram 机器人',
      cookbook: '操作手册',
      useCases: '使用场景',
    },
    hero: {
      kicker: '可路由 VPN 控制面',
      title: '一个连接。覆盖所有网络。无静默回退。',
      text: '将设备和私有目的网段固定到你选择的 egress；当路径失效时直接关闭该流，不做静默直连切换。',
      actions: [
        { label: '部署主机', url: '/vpn-hub/zh-cn/docs/start/install/' },
        { label: '查看 GitHub', url: 'https://github.com/rekurt/vpn-hub' },
      ],
    },
    architecture: {
      id: 'architecture',
      heading: '路由构建方式',
      text: '一个期望状态文件驱动重放。hubctl 保留注释，agent 应用规则，单一变更门串行化网络更新。',
      steps: [
        '策略文件定义设备、隧道、egress 角色与 DNS 范围',
        'agent 从策略渲染 namespace、nftables 规则与服务单元',
        '所有外发流量先经过 namespace 与策略检查后才放行',
      ],
    },
    protocols: {
      id: 'protocols',
      heading: '支持的入口与出口',
      items: [
        { name: 'Direct egress', role: '应急路径', notes: '仅显式配置，避免自动静默回退。' },
        { name: 'WireGuard', role: '主隧道', notes: '一个隧道、一个命名空间、可复现策略。' },
        { name: 'AmneziaWG', role: '客户端接入', notes: '混淆参数随配置与配置文件轮转一起更新。' },
        { name: 'Xray / VLESS', role: '替代传输', notes: '每隧道独立 namespace 和显式 profile。' },
        { name: 'OpenVPN', role: '兼容旧提供商', notes: '兼容混合环境的过渡流量。' },
      ],
    },
    safety: {
      id: 'safety',
      heading: '安全模型',
      text: '核心目标是明确路由路径和可测的漂移修复。',
      checks: [
        '安装、卸载与状态变更只允许 root 执行。',
        '策略异常时不允许静默回退到直连。',
        '外部提供商输入在重建前经过严格校验。',
        'Telegram profile 不存储主机私钥，只保留可控的最小凭证。',
        '文档化 SSH 兜底流程，支持 dry-run 与确认窗口。',
      ],
    },
    useCases: {
      id: 'use-cases',
      heading: '支持的使用场景',
      items: [
        { title: '按目的地址分流', category: '网络', summary: '将企业流量、私有网段与公共访问按目的分配到不同 egress。', commandHint: 'hubctl tunnel routes corp-private --add 203.0.113.0/24' },
        { title: '家庭办公走指定隧道', category: '连通性', summary: '所有终端固定走指定 egress，按需快速切换。', commandHint: 'hubctl device set-egress laptop corp-egress' },
        { title: '访问私有服务', category: '安全', summary: '仅允许私有 DNS 与私有子网流量通过专用隧道。', commandHint: 'hubctl tunnel routes corp-private --add 192.0.2.0/24' },
        { title: 'SOCKS5 应用定向', category: '操作', summary: '只将目标应用流量转入指定通道，不影响全局路由。', commandHint: 'hubctl routes' },
        { title: '供应商迁移与回滚', category: '可用性', summary: '候选源先走 canary 验证；失败时恢复 last-known-good。', commandHint: 'hubctl subscription refresh corp-egress' },
        { title: '设备隔离', category: '安全', summary: '默认禁止客户端互访，仅显式 ACL 例外。', commandHint: 'hubctl client-acl add phone laptop tcp/22' },
        { title: '故障处理与回退', category: '可靠性', summary: '可疑变更可通过带确认窗口的部署回退。', commandHint: 'hubctl deploy --confirm-within 5m' },
        { title: '私有 DNS 划分', category: '网络', summary: '私有域名在隧道内解析，公共流量保持正常解析策略。', commandHint: 'hubctl tunnel zones corp-net --add corp.example' },
        { title: '计划停用隧道', category: '运维', summary: '在影响评估后停用单一隧道并保护依赖设备。', commandHint: 'hubctl tunnel disable corp-egress' },
        { title: '设备接入与配置发布', category: '生命周期', summary: '设备发布使用可追踪版本并防止地址冲突。', commandHint: 'hubctl device add laptop --egress corp-egress --address 198.51.100.10/32' },
        { title: '漂移检测', category: '合规', summary: '校验声明状态，并在运行状态偏离时受控重建。', commandHint: 'hubctl validate && hubctl deploy' },
        { title: '状态可观测性', category: '监控', summary: '部署前先确认 health、units 和待处理队列。', commandHint: 'hubctl status --format yaml' },
      ],
    },
    bot: {
      id: 'bot-management',
      heading: 'Telegram 运维示例',
      intro: '机器人支持预览变更、带回滚保护的确认和关键指标巡检。',
      steps: [
        '先确认当前修订版本与 drift / host 状态。',
        '查看变更预览并在倒计时内确认或回滚。',
        '通过聊天操作进行设备吊销或重发配置。',
        '在订阅更新前检查 canary 健康结果。',
      ],
    },
    cookbook: {
      id: 'cookbook',
      heading: '操作手册快览',
      intro: '提供可以直接复现的步骤。',
      links: [
        { title: '带回滚窗口的部署', description: '安全应用配置变更的标准流程。', url: '/vpn-hub/zh-cn/docs/cookbook/rolling-deploy/' },
        { title: '恢复与回滚流程', description: '异常状态下的处理与恢复步骤。', url: '/vpn-hub/zh-cn/docs/cookbook/rollback-runbook/' },
        { title: '零信任分段实践', description: '从单一配置文件构建隔离子网与 ACL。', url: '/vpn-hub/zh-cn/docs/cookbook/segmentation/' },
        { title: '订阅 canary 验证', description: '候选 upstream 的验证与晋升流程。', url: '/vpn-hub/zh-cn/docs/cookbook/subscription-canary/' },
      ],
    },
    finalCta: {
      id: 'next-steps',
      heading: '准备开始安全上线了吗？',
      text: '先使用一个可控配置文件验证流程，再逐步扩展用例。',
      actions: [
        { label: '阅读全文档', url: '/vpn-hub/zh-cn/docs/' },
        { label: '查看回滚流程', url: '/vpn-hub/zh-cn/docs/cookbook/rollback-runbook/' },
      ],
    },
  },
};

export function getLandingCopy(locale: LandingLocale): LandingCopy {
  return landingData[locale];
}
