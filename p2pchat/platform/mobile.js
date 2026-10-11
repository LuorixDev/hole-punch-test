(() => {
  'use strict';
  if (!window.Capacitor?.isNativePlatform()) return;
  const save = window.Capacitor.Plugins.P2PSaveFile;
  window.p2pPlatform = Object.freeze({platform: 'android', saveFile: request => save.saveFile(request)});
  const methods = ['udp-probe', 'quic', 'tcp', 'tcp-simopen', 'upnp', 'pcp', 'natpmp'];
  window.p2pNative = Object.freeze({
    invoke: async method => {
      if (method === 'capabilities') return {v: 1, methods: methods.map(mechanism => ({mechanism, status: 'unsupported', canMessage: false, reason: 'ANDROID_NATIVE_ADAPTER_NOT_IMPLEMENTED', limits: {}}))};
      throw new Error('ANDROID_NATIVE_ADAPTER_NOT_IMPLEMENTED');
    },
    onEvent: () => () => {}
  });
})();
