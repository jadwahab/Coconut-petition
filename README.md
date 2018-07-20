# Coconut-petition

Forked from [Jędrzej Stuczyński's Multi-Authority-SDC e-cash system](https://github.com/jstuczyn/Multi-Authority-SDC)!

### Running the system:

To run the system locally one can use the provided `startservers.sh` script that starts appropriate services in separate `tmux` windows. However, it requires that that all dependencies were already installed. This includes:
- running `npm install` and `npm build` within servers directory
- running `npm install` within client's directory
- installing docker
- creating SQL schema:

```
npm install knex -g

knex migrate:latest
```
