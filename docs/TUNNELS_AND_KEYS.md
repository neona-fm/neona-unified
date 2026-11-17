# Где брать ключи и как настраивать два MCP-туннеля

В программе используются **разные типы секретов**. Их нельзя путать.

| Название | Где получать | Для чего |
|---|---|---|
| VPN-подписка/URL узла | У вашего VPN-провайдера | Зарубежное подключение через Xray и разделение маршрутов RU/не-RU |
| Служебный API-ключ OpenAI | [OpenAI Platform → API Keys](https://platform.openai.com/settings/organization/api-keys) | Аутентификация `tunnel-client` в control plane; разрешение **Tunnels: Read + Use** |
| Два Secure MCP Tunnel | [OpenAI Platform → Tunnels](https://platform.openai.com/settings/organization/tunnels) | Независимые подключения Windows MCP и Chrome MCP |
| Токен расширения Playwright Chrome | При настройке/сопряжении официального Chrome-расширения Playwright MCP | Соединение расширения с локальным Playwright MCP |

## Последовательность

1. В OpenAI Platform откройте раздел **Tunnels** и создайте два отдельных туннеля (один под Windows MCP, второй под Chrome MCP).
2. В разделе **API Keys** создайте ключ с типом **Restricted** («Ограниченный»), назначьте разрешение **Tunnels → Read + Use** («Туннели → чтение и использование»). Остальные разрешения, включая работу с моделями, выключите, если для клиента они не нужны. Ключ может использоваться клиентом для подключения двух профилей, если это соответствует вашей схеме доступа.
3. Скачайте официальный [OpenAI tunnel-client](https://github.com/openai/tunnel-client) для Windows. Настройте два профиля (в проверенной установке — `neona-windows` и `neona-chrome`) и свяжите каждый со своим туннелем.
4. Разверните Windows MCP-сервер в разрешённой папке. Для Chrome MCP настройте Playwright MCP через Node.js/npx с опцией `--extension` и свяжите браузерное расширение с работающим сервером.
5. В ChatGPT подключите **оба** MCP-сервера как пользовательские подключения, выбрав соответствующие туннели.
6. Укажите ключ OpenAI и токен Chrome в Neona Unified, сохраните; после VPN программа сможет запустить оба локальных клиента туннелей.
7. Проверьте реальные вызовы Windows MCP и Chrome MCP из ChatGPT. Если инструменты не вызываются, проверьте подключение/авторизацию отдельно — статус `ready` на localhost не доказывает end-to-end доступность.

## Полная инструкция со скриншотами

**[https://n-fm.ru/chatgpt-windows-chrome-mcp-instrukciya/](https://n-fm.ru/chatgpt-windows-chrome-mcp-instrukciya/)** — наше подробное руководство с шагами подготовки Windows, получения ключа, создания туннелей, установки сервера и расширения. Здесь приведено только краткое резюме для пользователей Neona Unified.

## Безопасность

- Никогда не публикуйте API-ключи, VPN-подписки, `settings.json`, `profile.dpapi`, `active.json`, `probe.json`, токены расширения, журналы с секретами.
- Не путайте Restricted API key для OpenAI Tunnels и подписку VPN-провайдера — это принципиально разные вещи.
- Не пересылайте секреты в открытых issue GitHub и снимках экрана.
