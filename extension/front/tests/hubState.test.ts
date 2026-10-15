const { expect } = require("chai");

describe("hub state storage", () => {
  let previousWindow;

  beforeEach(() => {
    previousWindow = global.window;
    const values = new Map();
    global.window = {
      localStorage: {
        getItem: (key) => values.has(key) ? values.get(key) : null,
        setItem: (key, value) => values.set(key, String(value)),
      },
    };
    delete require.cache[require.resolve("../shared/hubState")];
    require("../shared/hubState");
  });

  afterEach(() => {
    global.window = previousWindow;
  });

  it("removes obsolete chat payloads without touching UI preferences", () => {
    window.POFHubState.saveStorage({
      ollamaConversation: [{ role: "user", content: "legacy" }],
      ollamaConversationHistory: [{ id: "legacy" }],
      ollamaActiveConversationId: "legacy",
      ollamaHistorySort: "title_asc",
    });

    const result = window.POFHubState.removeStorageKeys([
      "ollamaConversation",
      "ollamaConversationHistory",
      "ollamaActiveConversationId",
    ]);

    expect(result).to.deep.equal({ ollamaHistorySort: "title_asc" });
    expect(window.POFHubState.loadStorage()).to.deep.equal(result);
  });
});
