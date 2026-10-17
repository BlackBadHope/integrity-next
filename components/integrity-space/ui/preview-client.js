// Ephemeral local preview authentication. No storage, URL token, ambient cookies or logs.
export function createPreviewClient(fetcher = fetch) {
  let token = '';
  async function request(path, payload) {
    if (!token) throw new Error('Введите локальный код подключения.');
    const reply = await fetcher(path, {
      method: payload === undefined ? 'GET' : 'POST',
      headers: {'Content-Type': 'application/json', Authorization: 'Bearer ' + token},
      credentials: 'omit', cache: 'no-store', mode: 'same-origin',
      ...(payload === undefined ? {} : {body: JSON.stringify(payload)})
    });
    if (!reply.ok) {
      if (reply.status === 401) token = '';
      const error = new Error(reply.status === 401 ? 'Нет доступа. Введите локальный код подключения ещё раз.' : 'Локальный источник недоступен.');
      error.code = reply.status === 401 ? 'access_denied' : 'connection_error';
      throw error;
    }
    return reply.json();
  }
  return Object.freeze({
    async connect(value) {
      token = '';
      if (typeof value !== 'string' || value.length < 32 || value.length > 4096 || /[^\x21-\x7e]/.test(value))
        throw new Error('Неверный формат локального кода подключения.');
      token = value;
      try { return await request('/preview/bootstrap'); }
      catch (error) { token = ''; throw error; }
    },
    call(name, args = {}) { return request('/preview/tool', {name, arguments: args}); },
    clear() { token = ''; }
  });
}
