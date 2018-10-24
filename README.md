# Coconut-petition
Paper published [here](https://arxiv.org/abs/1809.10956)

In this dissertation project, we describe and implement a practical system application based on a selective disclosure credential scheme, namely the Coconut credential scheme[1]. The specific application here is an electronic petition system with the distinctive added feature of unlinkability as well as anonymity: such that no information about the anonymous petition voter is linkable back to the individual. In other words, there is no data leaked about who voted in the petition, just that the users who did, were indeed eligible and authorized to vote. As for the implementation, the client-side is done using JavaScript so that the client can trustlessly compute the cryptographic constructions individually, whereas the server-side is done using Node.js, but can easily be replaced by a more sophisticated and secure structure such as a permissionless blockchain platform.

Code forked from [Jędrzej Stuczyński's Multi-Authority-SDC e-cash system](https://github.com/jstuczyn/Multi-Authority-SDC)!

### System Setup:
- Run `npm install` within `/client` directory
- Run `npm install` and `npm run build` within `/servers` directory

#### Start processes in separate `tmux` windows:
- Install `tmux` if you don't have it:
- Run the `start.sh` script in the root directory
