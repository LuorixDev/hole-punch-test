(() => {
  'use strict';
  if (!window.Capacitor?.isNativePlatform()) return;
  const save = window.Capacitor.Plugins.P2PSaveFile;
  const listeners=new Set(),streams=new Set();let paused=false;
  const emit=type=>{if(type==='pause'){if(paused)return;paused=true;for(const stream of streams)for(const track of stream.getTracks())track.stop();streams.clear();}else if(type==='resume'){if(!paused)return;paused=false;}for(const fn of listeners)fn({type,paused});};
  // Called by trusted native activity and visibility fallback. No credentials/data.
  window.p2pMobileLifecycle=emit;
  window.document?.addEventListener('visibilitychange',()=>emit(window.document.hidden?'pause':'resume'));
  window.addEventListener?.('offline',()=>emit('network-change'));
  window.addEventListener?.('online',()=>emit('network-change'));
  window.navigator?.connection?.addEventListener('change',()=>emit('network-change'));
  window.p2pPlatform = Object.freeze({platform: 'android', saveFile: request => save.saveFile(request),trackStream:stream=>{if(paused){stream.getTracks().forEach(t=>t.stop());return false;}streams.add(stream);return true;},untrackStream:stream=>streams.delete(stream),onLifecycle:fn=>{listeners.add(fn);return()=>listeners.delete(fn);}});
  const methods = ['udp-probe', 'quic', 'tcp', 'tcp-simopen', 'upnp', 'pcp', 'natpmp'];
  window.p2pNative = Object.freeze({
    invoke: async method => {
      if (method === 'capabilities') return {v: 1, methods: methods.map(mechanism => ({mechanism, status: 'unsupported', canMessage: false, reason: 'ANDROID_NATIVE_ADAPTER_NOT_IMPLEMENTED', limits: {}}))};
      throw new Error('ANDROID_NATIVE_ADAPTER_NOT_IMPLEMENTED');
    },
    onEvent: () => () => {}
  });
})();
