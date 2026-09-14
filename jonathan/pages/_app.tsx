import { Toaster } from 'react-hot-toast';
import { QueryClient, QueryClientProvider } from 'react-query';
import { appWithTranslation } from 'next-i18next';
import type { AppProps } from 'next/app';
import { Inter } from 'next/font/google';

import { HomeProvider } from '@/pages/api/home/home.context';
import { PluginProvider } from '@/hooks/PluginProvider';

import '@/styles/globals.css';
import { PremiumStatusProvider } from '@/hooks/PremiumStatusContext';

const inter = Inter({ subsets: ['latin'] });

function App({ Component, pageProps }: AppProps<{}>) {
  const queryClient = new QueryClient();

  return (
    <div className={inter.className}>
      <Toaster />
      <QueryClientProvider client={queryClient}>
        <HomeProvider>
          <PremiumStatusProvider>
            <PluginProvider>
              <Component {...pageProps} />
            </PluginProvider>
          </PremiumStatusProvider>
        </HomeProvider>
      </QueryClientProvider>
    </div>
  );
}

export default appWithTranslation(App);
