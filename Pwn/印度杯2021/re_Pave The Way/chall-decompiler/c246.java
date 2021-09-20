class c246 {
   public static void main(String[] var0) throws Exception {
      System.out.print("Paving your way.");
      pave("");
   }

   public static void pave(String var0) throws Exception {
      var0 = var0 + "N";
      System.out.print(".");
      Thread.sleep(3600000L);
      c8.pave(var0);
   }
}
