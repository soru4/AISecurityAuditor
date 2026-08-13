package com.auditor;
import com.threadpool.ThreadPool;
import com.threadpool.ThreadSafeTaskQueue;

public class Main {
    /** 
     * @param args
     */
    public static void main(String[] args) {
        ThreadSafeTaskQueue queue = new ThreadSafeTaskQueue();
        ThreadPool pool = new ThreadPool(5, queue);

        System.out.println("Custom JAR loaded via Maven!");
    }
}