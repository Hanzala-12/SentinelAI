chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === 'GET_PAGE_CONTEXT') {
    sendResponse({
      ok: true,
      context: {
        text: document.body?.innerText?.slice(0, 10000) ?? '',
        html: document.documentElement?.outerHTML?.slice(0, 200000) ?? '',
        title: document.title,
        url: location.href,
      },
    })
    return true
  }
  return undefined
})
