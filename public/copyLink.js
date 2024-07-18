function copyLink(id) {
    navigator.clipboard.writeText(`http://localhost:3000/q/${id}`);

    // navigator.share({ url: "https://localhost:3000/q/{{ id }}" });
}