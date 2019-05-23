/*
 * MIT License
 *
 * Copyright (c) 2019 dsafa22, All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.fang.myapplication;

import android.util.Log;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class AirPlayServer {

    public static String TAG = "AirPlayServer";

    private ServerSocket mServerSocket = null;
    private ServerThread mServerThread = null;

    public AirPlayServer() {

    }


    public void startServer() {
        try {
            mServerSocket = new ServerSocket(0);
        } catch (IOException e) {
            e.printStackTrace();
        }
        mServerThread = new ServerThread();
        mServerThread.start();
    }

    public void stopServer() {
        try {
            mServerSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public int getPort() {
        if (mServerSocket != null) {
            return mServerSocket.getLocalPort();
        }
        return 0;
    }


    class ServerThread extends Thread {

        @Override
        public void run() {
            try {
                Socket socket = mServerSocket.accept();
                Log.d(TAG, "receive accept");
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }
}
