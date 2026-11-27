// prints env for debugging; never sends it anywhere
module.exports = () => console.log(JSON.stringify(process.env, null, 2));
