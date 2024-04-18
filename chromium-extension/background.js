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


getData(myurl);

chrome.tabs.query({ active: true, lastFocusedWindow: true }, tabs => {
    let url = tabs[0].url;
    console.log(url);
});
