document.addEventListener("DOMContentLoaded", function () {
  var dataPlaceholder = document.getElementById("data-placeholder");
  const urlPlacholder = document.getElementById("url-placeholder");

  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    var activeTab = tabs[0];

    urlPlacholder.textContent = activeTab.url;

    fetch("http://localhost:8000/?url=" + encodeURIComponent(activeTab.url))
      .then((response) => response.json())
      .then((data) => {
        console.log("data: ", data);
        dataPlaceholder.textContent = data.accuracy;
      })
      .catch((error) => {
        console.error("Error fetching data:", error);
        dataPlaceholder.textContent = "Error fetching data";
      });
  });
});
