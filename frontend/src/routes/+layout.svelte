<script>
	import '../app.css';
</script>

<div id="wip" class="px-5 py-5 md:text-5xl md:w-14 shadow-lg">WIP!</div>

<slot />

<style>
	#wip {
		position: absolute;
		z-index: 2;
		top: 100px;
		right: 0;
		padding-right: 20px;
		width: 150px;
		text-align: center;
		background-color: #f4d2d8;
		border-top-left-radius: 10px;
		border-bottom-left-radius: 10px;
	}
</style>
