<script lang="ts">
  let clicked = false;
  let resp: string;

  let url = "";

  function handleClick() {
    fetch(`http://localhost:8000/?url=${url}`)
      .then((response) => response.json())
      .then((data) => {
        resp = data;
        clicked = true;
      });
  }
</script>

<h1>Prediction</h1>

<input bind:value={url} />

<table>
  <thead></thead>
  <tbody></tbody>
</table>

<button on:click={handleClick}>Submit</button>

{#if clicked}
  <p>{JSON.stringify(resp)}</p>
{/if}
