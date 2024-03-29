// TODO: Figure out how to get types from this lib:
import { ethers } from "ethers";
import EventEmitter from "events";
import Cookies from "js-cookie";
import { SiweMessage } from "siwe";
import type { ICoreOptions } from "web3modal";
import Web3Modal from "web3modal";

export interface SiweSession {
  message: SiweMessage;
  raw: string;
  signature: string;
  ens?: string;
  ensAvatar?: string;
}

export interface SessionOpts {
  domain: string;
  uri: string;
  useENS: boolean;
  version: string;
  // Defaults to 48 hours.
  expiration?: number;
  statement?: string;
  resources?: Array<string>;
}

export interface ClientOpts {
  session: SessionOpts;
  modal?: Partial<ICoreOptions>;
  currentSession?: SiweSession;
}

export class Client extends EventEmitter {
  provider: ethers.providers.JsonRpcProvider;
  modalOpts: Partial<ICoreOptions>;
  sessionOpts: SessionOpts;
  session: SiweSession;
  web3Modal: Web3Modal;

  constructor(opts: ClientOpts) {
    super();

    this.modalOpts = opts?.modal || {};
    this.session = opts?.currentSession;
    this.sessionOpts = opts.session;

    const sanity =
      typeof this.sessionOpts?.expiration === "number" &&
      this.sessionOpts?.expiration > 0;

    if (!sanity) {
      // Default to 48 hours.
      this.sessionOpts.expiration = 2 * 24 * 60 * 60 * 1000;
    }

    const sessionCookie = Cookies.get("siwe");
    if (sessionCookie) {
      const { message, signature, ens, ensAvatar } = JSON.parse(sessionCookie);
      this.session = {
        message: new SiweMessage(message),
        raw: message,
        signature,
        ens,
        ensAvatar,
      };
    }

    this.web3Modal = new Web3Modal({ ...this.modalOpts, cacheProvider: true });

    this.web3Modal.on("accountsChanged", (e) =>
      this.emit("accountsChanged", e)
    );
    this.web3Modal.on("chainChanged", (e) => this.emit("chainChanged", e));
    this.web3Modal.on("connect", (e) => this.emit("connect", e));
    this.web3Modal.on("disconnect", (e) => this.emit("disconnect", e));
  }

  async signOut() {
    this.provider = null;
    this.session = null;
    this.web3Modal.clearCachedProvider();

    Cookies.remove("siwe");
    this.emit("signOut");
  }

  async signIn(nonce?: string): Promise<SiweSession> {
    return new Promise(async (resolve, reject) => {
      let address;
      try {
        await this.initializeProvider();

        this.emit("modalClosed");

        // Get list of accounts of the connected wallet
        const accounts = await this.provider.listAccounts();

        // MetaMask does not give you all accounts, only the selected account
        const [_address] = accounts;
        if (!_address) {
          throw new Error("Address not found");
        }
        address = _address;
      } catch (e) {
        this.signOut();
        reject(e);
        return;
      }

      let ens, ensAvatar;
      try {
        ens = await this.provider.lookupAddress(address);
      } catch { }

      if(ens) {
        ensAvatar = `https://metadata.ens.domains/${this.provider.network.name}/avatar/${ens}`;
      }

      try {
        const expirationTime = new Date(
          new Date().getTime() + this.sessionOpts.expiration
        );
  
        const signMessage = new SiweMessage({
          domain: this.sessionOpts.domain,
          address: address,
          chainId: await this.provider
            .getNetwork()
            .then(({ chainId }) => chainId),
          expirationTime: expirationTime.toISOString(),
          uri: this.sessionOpts.uri,
          version: this.sessionOpts.version,
          statement: this.sessionOpts.statement,
          nonce,
          resources: this.sessionOpts.resources,
        }).prepareMessage();
  
        const signature = await this.provider
          .getSigner()
          .signMessage(signMessage);
        const message = new SiweMessage(signMessage);
        const session: SiweSession = {
          message,
          raw: signMessage,
          signature,
          ens,
          ensAvatar,
        };
        Cookies.set("siwe", JSON.stringify(session), {
          expires: expirationTime,
        });
  
        this.emit("signIn", session);
  
        resolve(session);
        return;
      } catch (e) {
        this.signOut();
        reject(e);
        return;
      }
    });
  }

  async validate() {
    if (this.session) {
      await this.initializeProvider();
    } else {
      return;
    }

    const result = await this.session.message.verify(
      {
        signature: this.session.signature,
        domain: this.sessionOpts.domain,
      },
      { provider: this.provider }
    );
    this.session.message = result.data;
    this.emit("validate", { session: this.session, error: result.error });
  }

  async initializeProvider(): Promise<ethers.providers.JsonRpcProvider> {
    return new Promise<ethers.providers.JsonRpcProvider>((resolve, reject) => {
      if (!this.provider) {
        return this.web3Modal
          .connect()
          .then((provider) => {
            this.provider = new ethers.providers.Web3Provider(provider);
            resolve(this.provider);
          })
          .catch(reject);
      } else {
        resolve(this.provider);
      }
    });
  }
}
