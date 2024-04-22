async function getCurrentTab() {
    let queryOptions = { active: true, lastFocusedWindow: true };
    let [tab] = await chrome.tabs.query(queryOptions);
    localStorage.setItem("url", tab.url);
	console.log(tab);
	return tab;
}

getCurrentTab();