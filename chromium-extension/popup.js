document.addEventListener("DOMContentLoaded", function () {
  const dataPlaceholder = document.getElementById("data-placeholder");
  const urlPlacholder = document.getElementById("url-placeholder");

  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const activeTab = tabs[0];

    urlPlacholder.textContent = activeTab.url;

    fetch("http://localhost:8000/?url=" + encodeURIComponent(activeTab.url))
      .then((response) => response.json())
      .then((data) => {
        console.log("data: ", data);
        dataPlaceholder.textContent = Math.round(data.accuracy*100) + '%';
      })
      .catch((error) => {
        console.error("Error fetching data:", error);
        dataPlaceholder.textContent = "Error fetching data";
      });
  });
});
