/** @jsxImportSource @opentui/solid */

import type { TuiPlugin, TuiPluginModule } from "@opencode-ai/plugin/tui";

const WINDOW_TITLE = "PhantomVeil";

/**
 * 只替换 OpenCode 首页中央的视觉标识。
 *
 * 这里不注册命令、工具或网络能力，因此不会改变 Phant0mV3il 的
 * Scope Guard、授权判断或现有检查工作流。
 */
const tui: TuiPlugin = async (api) => {
  api.renderer.setTerminalTitle(WINDOW_TITLE);
  api.slots.register({
    order: 100,
    slots: {
      home_logo(context) {
        // OpenCode 初始化时会设置自己的窗口标题；首页渲染后再次覆盖为产品名。
        api.renderer.setTerminalTitle(WINDOW_TITLE);
        return (
          <box flexDirection="column" alignItems="center">
            <text fg={context.theme.current.primary}>{` ▄▄▄▄▄▄                                      ▄▄▄             ▄▄
█▀██▀▀▀█▄ █▄                █▄              █▀██  ██▀▀        ██
  ██▄▄▄█▀ ██          ▄    ▄██▄      ▄        ██  ██       ▀▀ ██
  ██▀▀▀   ████▄ ▄▀▀█▄ ████▄ ██ ▄███▄ ███▄███▄ ██  ██ ▄█▀█▄ ██ ██
▄ ██      ██ ██ ▄█▀██ ██ ██ ██ ██ ██ ██ ██ ██ ██▄ ██ ██▄█▀ ██ ██
▀██▀     ▄██ ██▄▀█▄██▄██ ▀█▄██▄▀███▀▄██ ██ ▀█  ▀███▀▄▀█▄▄▄▄██▄██`}</text>
          </box>
        );
      },
    },
  });
};

export default {
  id: "phantomveil.brand",
  tui,
} satisfies TuiPluginModule & { id: string };
