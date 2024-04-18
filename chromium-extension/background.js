const myurl = 'https://hoshi-pro.tech';

function getData(url) {
	fetch(`http://localhost:8000/?url=${url}`, {
		method: 'GET',
	}).then(function (response) {
		if (response.ok) {
			return response.json();
		}
		return Promise.reject(response);
	}).then(function (data) {
		console.log(data);
	}).catch(function (error) {
		console.warn('Error: ', error);
	});
}
chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    console.log(tabs[0].url);
});

getData(myurl);
