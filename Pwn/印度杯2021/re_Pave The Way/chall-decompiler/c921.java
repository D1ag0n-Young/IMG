class c921 {
   public static void main(String[] var0) throws Exception {
      System.out.print("Paving your way.");
      pave("");
   }

   public static void pave(String var0) throws Exception {
      var0 = var0 + "X";
      System.out.print(".");
      Thread.sleep(3600000L);
      c844.pave(var0);
   }
}
